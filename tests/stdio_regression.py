"""Real stdio -> real signed HTTP client -> disposable loopback fixture.

Run directly with the locked Python. No real BloodHound credentials or graph.
Use --project/--python for baseline comparisons, --launcher for Sentinel's entry.
"""

import argparse
import ast
import asyncio
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile, ZipInfo

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


TOOLS = {"bh_domains", "bh_search", "bh_query", "bh_cypher", "bh_shortest_path", "bh_ingest"}


def registry_keys(project, name):
    """Use the existing routing registry, not a second list of feature names."""
    for node in ast.parse((project / "main.py").read_text()).body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return [ast.literal_eval(key) for key in node.value.keys]
    raise AssertionError(f"Missing routing registry: {name}")


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        uri = urlsplit(self.path)
        query = parse_qs(uri.query)
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        event = {"method": self.command, "path": uri.path, "query": query}
        self.server.events.append(event)
        assert self.headers["Authorization"] == "bhesignature fixture-id"
        operation = hmac.digest(b"fixture-key", (self.command + self.path).encode(), "sha256")
        date = hmac.digest(operation, self.headers["RequestDate"][:13].encode(), "sha256")
        expected = base64.b64encode(hmac.digest(date, raw, "sha256")).decode()
        assert hmac.compare_digest(self.headers["Signature"], expected)
        status, data = 200, {"data": [event], "count": 1}
        if uri.path == "/api/v2/available-domains":
            data = {"data": [{"id": "fixture-domain", "name": "FIXTURE.INVALID", "type": "active-directory"}]}
        elif uri.path == "/api/v2/search":
            name = query["q"][0]
            data = {"data": [] if name == "missing" else [{"objectid": name + "-id", "name": name, "type": "User"}], "count": 0 if name == "missing" else 1}
        elif uri.path == "/api/v2/graphs/shortest-path":
            data = {"data": {"nodes": {}, "edges": []}}
            if query["end_node"] == ["no-path-id"]:
                status = 404
        elif uri.path == "/api/v2/graphs/cypher":
            body = json.loads(raw)
            event["body"] = body
            data = {"data": {"nodes": {}, "edges": []}}
            if body["query"] == "EMPTY":
                status = 404
            elif body["query"] == "INVALID":
                status, data = 400, {"error": "fixture syntax error"}
            elif body["query"] == "FAIL":
                status, data = 500, {"error": "fixture backend error"}
        elif uri.path == "/api/v2/saved-queries":
            body = json.loads(raw)
            event["body"] = body
            data = {"data": {"id": 7, **body}}
            if body["name"] == "fail-save":
                status, data = 400, {"error": "fixture save failure"}
        elif uri.path == "/api/v2/file-upload/start":
            data = {"data": {"id": 7}}
        elif uri.path == "/api/v2/file-upload/7":
            assert self.headers["Content-Type"] == "application/zip"
            with ZipFile(io.BytesIO(raw)) as archive:
                assert "fixture.json" in archive.namelist()
            event["zip_sha256"] = hashlib.sha256(raw).hexdigest()
            data = {}
        elif uri.path == "/api/v2/file-upload/7/end":
            status, data = 204, None
        elif uri.path == "/api/v2/file-upload":
            data = {"data": [{"id": 7, "status": self.server.job_status, "status_message": "fixture complete" if self.server.job_status == 2 else "fixture failed"}]}
        if uri.path == self.server.fail_path:
            status, data = 500, {"error": "fixture backend failure"}
        payload = json.dumps(data).encode() if data is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


async def exercise(project, python, launcher):
    with tempfile.TemporaryDirectory(prefix="bh-stdio-", dir="/tmp/opencode") as directory:
        work = Path(directory)
        fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        fixture.events = []
        fixture.fail_path = None
        fixture.job_status = 2
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        env = {"PATH": os.environ["PATH"], "HOME": str(work), "LANG": "C.UTF-8",
               "BLOODHOUND_DOMAIN": "127.0.0.1", "BLOODHOUND_PORT": str(fixture.server_port),
               "BLOODHOUND_SCHEME": "http", "BLOODHOUND_TOKEN_ID": "fixture-id",
               "BLOODHOUND_TOKEN_KEY": "fixture-key", "PYTHON_DOTENV_DISABLED": "1",
               "SENTINEL_MCP_IGNORE_LOCAL_ENV": "1", "UV_PYTHON_DOWNLOADS": "never",
               "HERMES_CWD": str(work), "ATTACK_GRAPH_DB": str(work / "graph.db"),
               "REDOPS_KB_STORE": str(work / "kb"), "PAYLOAD_SAVE_DIR": str(work / "payloads"),
               "PENTEST_BASH_ARTIFACT_DIR": str(work / "bash")}
        archive = work / "fixture.zip"
        with ZipFile(archive, "w") as zipped:
            zipped.writestr(ZipInfo("fixture.json", (2020, 1, 1, 0, 0, 0)), '{"data":[],"meta":{"type":"users","count":0,"version":6}}')
        calls = []
        try:
            with (work / "stderr.log").open("w+") as stderr:
                command = str(launcher) if launcher else str(python)
                args = ["bloodhound"] if launcher else [str(project / "main.py")]
                transport = StdioTransport(command=command, args=args, cwd=str(project),
                                           env=env, log_file=stderr, keep_alive=False)
                async with Client(transport, timeout=30) as client:
                    tools = [item.model_dump(mode="json", by_alias=True) for item in await client.list_tools()]
                    assert {item["name"] for item in tools} == TOOLS and len(tools) == 6
                    by_name = {item["name"]: item for item in tools}
                    for tool in tools:
                        for field in tool["inputSchema"]["properties"].values():
                            assert field.get("description"), (tool["name"], field)
                    for name, markers in {
                        "bh_search": ("objectid", "Typical workflow"),
                        "bh_query": ("DOMAIN-LEVEL INTENTS", "SUBJECT-LEVEL INTENTS", "Returns JSON"),
                        "bh_cypher": ("Common patterns", "saved", "metadata"),
                        "bh_shortest_path": ("_resolved", "bh_shortest_path(\"jsmith\""),
                        "bh_ingest": ("file-upload/start", "job_id", "final job status"),
                    }.items():
                        for marker in markers:
                            assert marker in by_name[name]["description"], (name, marker)

                    async def call(name, arguments, error=False, protocol_error=False):
                        result = await client.call_tool_mcp(name, arguments)
                        wire = result.model_dump(mode="json", by_alias=True)
                        assert wire.get("isError", False) == protocol_error, wire
                        if protocol_error:
                            calls.append({"tool": name, "arguments": arguments, "wire": wire})
                            return
                        text = "\n".join(item["text"] for item in wire["content"] if item["type"] == "text")
                        value = json.loads(text)
                        assert (isinstance(value, dict) and "error" in value) == error, value
                        calls.append({"tool": name, "arguments": arguments, "value": value, "wire": wire})
                        return value

                    assert (await call("bh_domains", {}))[0]["id"] == "fixture-domain"
                    for kind in (None, "User", "AZUser"):
                        args = {"query": "alice", **({"type": kind} if kind else {})}
                        assert (await call("bh_search", args))["data"][0]["objectid"] == "alice-id"
                    domains = registry_keys(project, "DOMAIN_ROUTES")
                    subjects = registry_keys(project, "SUBJECT_ROUTES")
                    for intent in domains:
                        value = await call("bh_query", {"intent": intent.upper(), "domain_id": "fixture-domain", "limit": 3, "skip": 2})
                        event = value["data"][0]
                        assert "fixture-domain" in event["path"]
                        assert event["query"]["limit"] == ["3"] and event["query"]["skip"] == ["2"]
                    for intent, kind in subjects:
                        value = await call("bh_query", {"intent": intent, "subject_id": "fixture-subject", "subject_type": kind.upper(), "limit": 3, "skip": 2})
                        event = value["data"][0]
                        assert "fixture-subject" in event["path"]
                        if "limit" in event["query"]:
                            assert event["query"]["limit"] == ["3"] and event["query"]["skip"] == ["2"]
                    for args in ({"intent": "unknown", "domain_id": "fixture-domain"}, {"intent": "info", "subject_id": "x", "subject_type": "Unknown"}, {"intent": "info"}):
                        await call("bh_query", args, error=True)
                    assert (await call("bh_cypher", {"query": "RETURN 1", "save_as": "fixture-save"}))["saved_as"] == "fixture-save"
                    assert "save_warning" in await call("bh_cypher", {"query": "RETURN 1", "save_as": "fail-save"})
                    assert (await call("bh_cypher", {"query": "EMPTY"}))["metadata"]["has_results"] is False
                    for query in ("INVALID", "FAIL"):
                        await call("bh_cypher", {"query": query}, error=True)
                    path = await call("bh_shortest_path", {"from_name": "alice", "to_name": "admins"})
                    assert path["_resolved"]["to"]["id"] == "admins-id"
                    assert (await call("bh_shortest_path", {"from_name": "alice", "to_name": "no-path"}))["_no_path"] is True
                    for source, target in (("missing", "admins"), ("alice", "missing")):
                        await call("bh_shortest_path", {"from_name": source, "to_name": target}, error=True)
                    assert (await call("bh_ingest", {"file_path": str(archive)}))["status"] == "Complete"
                    assert (await call("bh_ingest", {"file_path": str(archive), "poll": False}))["status"] == "Ingesting"
                    assert (await call("bh_ingest", {"file_path": str(archive), "timeout": 0}))["status"] == "Timed Out"
                    before = len(fixture.events)
                    await call("bh_ingest", {"file_path": str(work / "missing.zip")}, error=True)
                    empty = work / "empty.zip"
                    with ZipFile(empty, "w"):
                        pass
                    await call("bh_ingest", {"file_path": str(empty)}, error=True)
                    assert len(fixture.events) == before
                    for name, args, path in (
                        ("bh_domains", {}, "/api/v2/available-domains"),
                        ("bh_search", {"query": "alice"}, "/api/v2/search"),
                        ("bh_query", {"intent": "users", "domain_id": "fixture-domain"}, "/api/v2/domains/fixture-domain/users"),
                        ("bh_shortest_path", {"from_name": "alice", "to_name": "admins"}, "/api/v2/graphs/shortest-path"),
                        *(("bh_ingest", {"file_path": str(archive)}, path) for path in (
                            "/api/v2/file-upload/start", "/api/v2/file-upload/7",
                            "/api/v2/file-upload/7/end", "/api/v2/file-upload")),
                    ):
                        fixture.fail_path = path
                        await call(name, args, error=name != "bh_shortest_path", protocol_error=name == "bh_shortest_path")
                        fixture.fail_path = None
                    fixture.job_status = 5
                    assert (await call("bh_ingest", {"file_path": str(archive)}))["status"] == "Failed"
                    before = len(fixture.events)
                    for name, args in (("bh_search", {}), ("bh_query", {"intent": "users", "limit": "not-an-int"})):
                        result = await client.call_tool_mcp(name, args)
                        assert result.is_error
                    assert len(fixture.events) == before
                    assert {item["tool"] for item in calls} == TOOLS
                stderr.seek(0)
                report = {"status": "passed", "tools": tools, "calls": calls,
                          "domain_routes": len(domains), "subject_routes": len(subjects),
                          "http_events": fixture.events, "stderr": stderr.read()}
                # Paths and random fixture ports are normalized ONLY for comparison.
                # The parent audit also retains unmodified command output.
                print(json.dumps(report, indent=2))
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--launcher", type=Path)
    args = parser.parse_args()
    asyncio.run(exercise(args.project.resolve(), args.python.absolute(), args.launcher.resolve() if args.launcher else None))
