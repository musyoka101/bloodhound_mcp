#!/usr/bin/env python3
"""
BloodHound MCP Server — RedOps Integration
6-tool intent-dispatch design for use with RedOps AI red-team agents.

Tools:
  bh_domains        — list all domains (bootstrap)
  bh_search         — resolve a name/SID to objectid + type
  bh_query          — intent-based query dispatch (users, groups, sessions, etc.)
  bh_cypher         — raw Cypher query + optional save
  bh_shortest_path  — auto-resolve names → shortest attack path
  bh_ingest         — upload a SharpHound/AzureHound ZIP and trigger ingest
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from lib.bloodhound_api import (
    BloodhoundAPI,
    BloodhoundAPIError,
    BloodhoundConnectionError,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

load_dotenv()

mcp = FastMCP("bloodhound_mcp")

# ---------------------------------------------------------------------------
# Lazy singleton — only instantiated on first tool call so startup never
# fails when env vars are absent (e.g. during OpenCode MCP probe).
# ---------------------------------------------------------------------------
_api: Optional[BloodhoundAPI] = None


def _get_api() -> BloodhoundAPI:
    global _api
    if _api is None:
        _api = BloodhoundAPI()
    return _api


# ---------------------------------------------------------------------------
# Routing tables — add new endpoints here, no other changes needed.
# ---------------------------------------------------------------------------

# Domain-level intents: intent → callable(api, domain_id, limit, skip)
DOMAIN_ROUTES: Dict[str, Any] = {
    "users": lambda api, d, lim, sk: api.domains.get_users(d, lim, sk),
    "groups": lambda api, d, lim, sk: api.domains.get_groups(d, lim, sk),
    "computers": lambda api, d, lim, sk: api.domains.get_computers(d, lim, sk),
    "controllers": lambda api, d, lim, sk: api.domains.get_controllers(d, lim, sk),
    "gpos": lambda api, d, lim, sk: api.domains.get_gpos(d, lim, sk),
    "ous": lambda api, d, lim, sk: api.domains.get_ous(d, lim, sk),
    "dc syncers": lambda api, d, lim, sk: api.domains.get_dc_syncers(d, lim, sk),
    "foreign admins": lambda api, d, lim, sk: api.domains.get_foreign_admins(
        d, lim, sk
    ),
    "foreign gpo controllers": lambda api, d, lim, sk: (
        api.domains.get_foreign_gpo_controllers(d, lim, sk)
    ),
    "foreign groups": lambda api, d, lim, sk: api.domains.get_foreign_groups(
        d, lim, sk
    ),
    "foreign users": lambda api, d, lim, sk: api.domains.get_foreign_users(d, lim, sk),
    "inbound trusts": lambda api, d, lim, sk: api.domains.get_inbound_trusts(
        d, lim, sk
    ),
    "outbound trusts": lambda api, d, lim, sk: api.domains.get_outbound_trusts(
        d, lim, sk
    ),
}

# Subject-level intents: (intent, subject_type) → callable(api, subject_id, limit, skip)
# subject_type is normalised to lowercase before lookup.
SUBJECT_ROUTES: Dict[tuple, Any] = {
    # --- Users ---
    ("info", "user"): lambda api, s, lim, sk: api.users.get_info(s),
    ("admin rights", "user"): lambda api, s, lim, sk: api.users.get_admin_rights(
        s, lim, sk
    ),
    ("constrained delegation", "user"): lambda api, s, lim, sk: (
        api.users.get_constrained_delegation_rights(s, lim, sk)
    ),
    ("controllables", "user"): lambda api, s, lim, sk: api.users.get_controllables(
        s, lim, sk
    ),
    ("controllers", "user"): lambda api, s, lim, sk: api.users.get_controllers(
        s, lim, sk
    ),
    ("dcom rights", "user"): lambda api, s, lim, sk: api.users.get_dcom_rights(
        s, lim, sk
    ),
    ("memberships", "user"): lambda api, s, lim, sk: api.users.get_memberships(
        s, lim, sk
    ),
    ("ps remote rights", "user"): lambda api, s, lim, sk: (
        api.users.get_ps_remote_rights(s, lim, sk)
    ),
    ("rdp rights", "user"): lambda api, s, lim, sk: api.users.get_rdp_rights(
        s, lim, sk
    ),
    ("sessions", "user"): lambda api, s, lim, sk: api.users.get_sessions(s, lim, sk),
    ("sql admin rights", "user"): lambda api, s, lim, sk: (
        api.users.get_sql_admin_rights(s, lim, sk)
    ),
    # --- Groups ---
    ("info", "group"): lambda api, s, lim, sk: api.groups.get_info(s),
    ("admin rights", "group"): lambda api, s, lim, sk: api.groups.get_admin_rights(
        s, lim, sk
    ),
    ("controllables", "group"): lambda api, s, lim, sk: api.groups.get_controllables(
        s, lim, sk
    ),
    ("controllers", "group"): lambda api, s, lim, sk: api.groups.get_controllers(
        s, lim, sk
    ),
    ("dcom rights", "group"): lambda api, s, lim, sk: api.groups.get_dcom_rights(
        s, lim, sk
    ),
    ("members", "group"): lambda api, s, lim, sk: api.groups.get_members(s, lim, sk),
    ("memberships", "group"): lambda api, s, lim, sk: api.groups.get_memberships(
        s, lim, sk
    ),
    ("ps remote rights", "group"): lambda api, s, lim, sk: (
        api.groups.get_ps_remote_rights(s, lim, sk)
    ),
    ("rdp rights", "group"): lambda api, s, lim, sk: api.groups.get_rdp_rights(
        s, lim, sk
    ),
    ("sessions", "group"): lambda api, s, lim, sk: api.groups.get_sessions(s, lim, sk),
    # --- Computers ---
    ("info", "computer"): lambda api, s, lim, sk: api.computers.get_info(s),
    ("admin rights", "computer"): lambda api, s, lim, sk: (
        api.computers.get_admin_rights(s, lim, sk)
    ),
    ("admin users", "computer"): lambda api, s, lim, sk: api.computers.get_admin_users(
        s, lim, sk
    ),
    ("constrained delegation", "computer"): lambda api, s, lim, sk: (
        api.computers.get_constrained_delegation_rights(s, lim, sk)
    ),
    ("constrained users", "computer"): lambda api, s, lim, sk: (
        api.computers.get_constrained_users(s, lim, sk)
    ),
    ("controllables", "computer"): lambda api, s, lim, sk: (
        api.computers.get_controllables(s, lim, sk)
    ),
    ("controllers", "computer"): lambda api, s, lim, sk: api.computers.get_controllers(
        s, lim, sk
    ),
    ("dcom rights", "computer"): lambda api, s, lim, sk: api.computers.get_dcom_rights(
        s, lim, sk
    ),
    ("dcom users", "computer"): lambda api, s, lim, sk: api.computers.get_dcom_users(
        s, lim, sk
    ),
    ("memberships", "computer"): lambda api, s, lim, sk: (
        api.computers.get_group_membership(s, lim, sk)
    ),
    ("ps remote rights", "computer"): lambda api, s, lim, sk: (
        api.computers.get_ps_remote_rights(s, lim, sk)
    ),
    ("ps remote users", "computer"): lambda api, s, lim, sk: (
        api.computers.get_ps_remote_users(s, lim, sk)
    ),
    ("rdp rights", "computer"): lambda api, s, lim, sk: api.computers.get_rdp_rights(
        s, lim, sk
    ),
    ("rdp users", "computer"): lambda api, s, lim, sk: api.computers.get_rdp_users(
        s, lim, sk
    ),
    ("sessions", "computer"): lambda api, s, lim, sk: api.computers.get_sessions(
        s, lim, sk
    ),
    ("sql admins", "computer"): lambda api, s, lim, sk: api.computers.get_sql_admins(
        s, lim, sk
    ),
    # --- OUs ---
    ("info", "ou"): lambda api, s, lim, sk: api.ous.get_info(s),
    ("computers", "ou"): lambda api, s, lim, sk: api.ous.get_computers(s, lim, sk),
    ("gpos", "ou"): lambda api, s, lim, sk: api.ous.get_gpos(s, lim, sk),
    ("groups", "ou"): lambda api, s, lim, sk: api.ous.get_groups(s, lim, sk),
    ("users", "ou"): lambda api, s, lim, sk: api.ous.get_users(s, lim, sk),
    # --- GPOs ---
    ("info", "gpo"): lambda api, s, lim, sk: api.gpos.get_info(s),
    ("computers", "gpo"): lambda api, s, lim, sk: api.gpos.get_computer(s, lim, sk),
    ("controllers", "gpo"): lambda api, s, lim, sk: api.gpos.get_controllers(
        s, lim, sk
    ),
    ("ous", "gpo"): lambda api, s, lim, sk: api.gpos.get_ous(s, lim, sk),
    ("tier zeros", "gpo"): lambda api, s, lim, sk: api.gpos.get_tier_zeros(s, lim, sk),
    ("users", "gpo"): lambda api, s, lim, sk: api.gpos.get_users(s, lim, sk),
    # --- ADCS: Certificate Templates ---
    ("info", "certtemplate"): lambda api, s, lim, sk: api.adcs.get_cert_template_info(
        s
    ),
    ("cert template controllers", "certtemplate"): lambda api, s, lim, sk: (
        api.adcs.get_cert_template_controllers(s, lim, sk)
    ),
    # --- ADCS: Root CAs ---
    ("info", "rootca"): lambda api, s, lim, sk: api.adcs.get_root_ca_info(s),
    ("root ca controllers", "rootca"): lambda api, s, lim, sk: (
        api.adcs.get_root_ca_controllers(s, lim, sk)
    ),
    # --- ADCS: Enterprise CAs ---
    ("info", "enterpriseca"): lambda api, s, lim, sk: api.adcs.get_enterprise_ca_info(
        s
    ),
    ("enterprise ca controllers", "enterpriseca"): lambda api, s, lim, sk: (
        api.adcs.get_enterprise_ca_controllers(s, lim, sk)
    ),
    # --- ADCS: AIA CAs ---
    ("aia ca controllers", "aiaca"): lambda api, s, lim, sk: (
        api.adcs.get_aia_ca_controllers(s, lim, sk)
    ),
}


# ---------------------------------------------------------------------------
# Tool 1 — bh_domains
# ---------------------------------------------------------------------------
@mcp.tool()
def bh_domains() -> str:
    """
    List all AD/Azure domains known to BloodHound CE.

    Returns a JSON list of domain objects. Each object contains:
      - id         : domain object ID (use as domain_id in bh_query)
      - name       : FQDN of the domain
      - type       : "active-directory" or "azure"
      - collected  : whether collection data exists

    Use this first to get domain IDs before calling bh_query with domain-level intents.
    """
    try:
        result = _get_api().domains.get_all()
        return json.dumps(result, indent=2)
    except (BloodhoundAPIError, BloodhoundConnectionError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool 2 — bh_search
# ---------------------------------------------------------------------------
@mcp.tool()
def bh_search(query: str, type: Optional[str] = None) -> str:
    """
    Search BloodHound for an object by name or SID/ObjectID.

    Args:
        query : Name or partial name to search (required).
                Examples: "domain admins", "dc01", "S-1-5-21-..."
        type  : Optional filter. AD types: User, Group, Computer, OU, GPO,
                Container, CertTemplate, RootCA, EnterpriseCA, AIACA, Trust.
                Azure types: AZUser, AZGroup, AZApp, AZTenant, AZDevice.

    Returns a JSON object with 'data' list. Each item contains:
      - objectid          : use as subject_id in bh_query or bh_shortest_path
      - type              : object type (use as subject_type in bh_query)
      - name              : display name
      - distinguishedname : DN (AD objects only)

    Typical workflow:
        1. bh_search("alice") -> get objectid + type for user alice
        2. bh_query("admin rights", subject_id=<id>, subject_type="User")
    """
    try:
        kwargs: dict = {"query": query, "limit": 50}
        if type:
            kwargs["type"] = type
        result = _get_api().domains.search_objects(**kwargs)
        return json.dumps(result, indent=2)
    except (BloodhoundAPIError, BloodhoundConnectionError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool 3 — bh_query
# ---------------------------------------------------------------------------
@mcp.tool()
def bh_query(
    intent: str,
    domain_id: Optional[str] = None,
    subject_id: Optional[str] = None,
    subject_type: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
) -> str:
    """
    Intent-based query dispatcher. Covers ~85 BloodHound API endpoints.

    Provide EITHER domain_id (domain-level query) OR subject_id + subject_type
    (subject-level query about a specific object). Not both.

    --- DOMAIN-LEVEL INTENTS (requires domain_id) ---
    "users"                   - all users in domain
    "groups"                  - all groups
    "computers"               - all computers
    "controllers"             - domain controllers
    "gpos"                    - all GPOs
    "ous"                     - all OUs
    "dc syncers"              - principals with DCSync rights
    "foreign admins"          - cross-domain admin principals
    "foreign gpo controllers" - cross-domain GPO controllers
    "foreign groups"          - cross-domain group memberships
    "foreign users"           - cross-domain users
    "inbound trusts"          - inbound domain trusts
    "outbound trusts"         - outbound domain trusts

    --- SUBJECT-LEVEL INTENTS (requires subject_id + subject_type) ---
    subject_type = "User":
      "info", "admin rights", "constrained delegation", "controllables",
      "controllers", "dcom rights", "memberships", "ps remote rights",
      "rdp rights", "sessions", "sql admin rights"

    subject_type = "Group":
      "info", "admin rights", "controllables", "controllers", "dcom rights",
      "members", "memberships", "ps remote rights", "rdp rights", "sessions"

    subject_type = "Computer":
      "info", "admin rights", "admin users", "constrained delegation",
      "constrained users", "controllables", "controllers", "dcom rights",
      "dcom users", "memberships", "ps remote rights", "ps remote users",
      "rdp rights", "rdp users", "sessions", "sql admins"

    subject_type = "OU":
      "info", "computers", "gpos", "groups", "users"

    subject_type = "GPO":
      "info", "computers", "controllers", "ous", "tier zeros", "users"

    subject_type = "CertTemplate":
      "info", "cert template controllers"

    subject_type = "RootCA":
      "info", "root ca controllers"

    subject_type = "EnterpriseCA":
      "info", "enterprise ca controllers"

    subject_type = "AIACA":
      "aia ca controllers"

    Args:
        intent       : One of the intent strings above (case-insensitive).
        domain_id    : Domain object ID (from bh_domains) - for domain-level queries.
        subject_id   : Object ID (from bh_search) - for subject-level queries.
        subject_type : Object type (from bh_search) - for subject-level queries.
        limit        : Max results to return (default 50).
        skip         : Pagination offset (default 0).

    Returns JSON with 'data' list and 'count'.
    """
    norm_intent = intent.strip().lower()
    norm_type = (subject_type or "").strip().lower()

    try:
        api = _get_api()

        # Domain-level path
        if domain_id and not subject_id:
            if norm_intent not in DOMAIN_ROUTES:
                valid = ", ".join(sorted(DOMAIN_ROUTES.keys()))
                return json.dumps(
                    {"error": f"Unknown domain intent '{intent}'. Valid: {valid}"}
                )
            result = DOMAIN_ROUTES[norm_intent](api, domain_id, limit, skip)
            return json.dumps(result, indent=2)

        # Subject-level path
        if subject_id and norm_type:
            key = (norm_intent, norm_type)
            if key not in SUBJECT_ROUTES:
                valid_for_type = sorted(
                    k[0] for k in SUBJECT_ROUTES if k[1] == norm_type
                )
                if valid_for_type:
                    return json.dumps(
                        {
                            "error": f"Unknown intent '{intent}' for type '{subject_type}'. Valid: {', '.join(valid_for_type)}"
                        }
                    )
                else:
                    valid_types = sorted(set(k[1] for k in SUBJECT_ROUTES))
                    return json.dumps(
                        {
                            "error": f"Unknown subject_type '{subject_type}'. Valid types: {', '.join(valid_types)}"
                        }
                    )
            result = SUBJECT_ROUTES[key](api, subject_id, limit, skip)
            return json.dumps(result, indent=2)

        return json.dumps(
            {
                "error": "Provide either domain_id (for domain-level queries) or subject_id + subject_type (for object-level queries)."
            }
        )

    except (BloodhoundAPIError, BloodhoundConnectionError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool 4 — bh_cypher
# ---------------------------------------------------------------------------
@mcp.tool()
def bh_cypher(query: str, save_as: Optional[str] = None) -> str:
    """
    Execute a raw Cypher query against the BloodHound Neo4j database.

    Use this for anything not covered by bh_query: custom attack paths,
    owned-node traversals, ADCS ESC chains, Azure paths, etc.

    Args:
        query   : Cypher query string.
        save_as : Optional name to save the query for future reuse.
                  If provided, the query is saved after successful execution.

    Returns JSON with:
      - success  : bool
      - data     : { nodes: [...], edges: [...] }
      - metadata : query info and status

    Common patterns:
      Find kerberoastable users:
        MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN u

      Find paths from owned to DA:
        MATCH p=shortestPath((s:Base)-[*1..]->(t:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
        WHERE COALESCE(s.system_tags,'') CONTAINS 'owned' RETURN p

      Find all DA members:
        MATCH (n)-[:MemberOf*1..]->(g:Group)
        WHERE g.name =~ '(?i)domain admins.*' RETURN n

      ASREPRoastable users:
        MATCH (u:User) WHERE u.dontreqpreauth=true AND u.enabled=true RETURN u
    """
    try:
        api = _get_api()
        result = api.cypher.run_query(query)

        if save_as and result.get("success"):
            try:
                api.cypher.create_saved_query(name=save_as, query=query)
                result["saved_as"] = save_as
            except Exception as save_err:
                result["save_warning"] = f"Query ran OK but could not save: {save_err}"

        return json.dumps(result, indent=2)
    except (BloodhoundAPIError, BloodhoundConnectionError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool 5 — bh_shortest_path
# ---------------------------------------------------------------------------
@mcp.tool()
def bh_shortest_path(from_name: str, to_name: str) -> str:
    """
    Find the shortest attack path between two objects by display name.

    Automatically resolves names to object IDs via bh_search, then calls
    the BloodHound shortest-path graph API.

    Args:
        from_name : Display name of the source node (e.g. "jsmith", "WORKSTATION01").
        to_name   : Display name of the target node (e.g. "Domain Admins", "DC01").

    Returns JSON graph data with nodes and edges showing the attack path,
    plus a '_resolved' field showing what IDs were used.

    Returns an error JSON if either name cannot be resolved.

    Examples:
        bh_shortest_path("jsmith", "Domain Admins")
        bh_shortest_path("WORKSTATION01", "DC01.CORP.LOCAL")
        bh_shortest_path("helpdesk@corp.local", "Enterprise Admins")
    """
    try:
        api = _get_api()

        # Resolve source
        src_results = api.domains.search_objects(query=from_name, limit=5)
        src_data = src_results.get("data", [])
        if not src_data:
            return json.dumps(
                {
                    "error": f"Could not resolve source '{from_name}' - no results from search."
                }
            )
        src_id = src_data[0]["objectid"]

        # Resolve target
        dst_results = api.domains.search_objects(query=to_name, limit=5)
        dst_data = dst_results.get("data", [])
        if not dst_data:
            return json.dumps(
                {
                    "error": f"Could not resolve target '{to_name}' - no results from search."
                }
            )
        dst_id = dst_data[0]["objectid"]

        result = api.graph.get_shortest_path(start_node=src_id, end_node=dst_id)
        result["_resolved"] = {
            "from": {"name": from_name, "id": src_id},
            "to": {"name": to_name, "id": dst_id},
        }
        return json.dumps(result, indent=2)

    except (BloodhoundAPIError, BloodhoundConnectionError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool 6 — bh_ingest
# ---------------------------------------------------------------------------
@mcp.tool()
def bh_ingest(file_path: str, poll: bool = True, timeout: int = 300) -> str:
    """
    Upload a SharpHound or AzureHound collection ZIP to BloodHound CE and trigger ingest.

    Executes the 3-step BloodHound CE file upload job:
      1. POST /api/v2/file-upload/start         → create upload job
      2. POST /api/v2/file-upload/{id}           → upload raw zip bytes
      3. POST /api/v2/file-upload/{id}/end       → signal upload complete, trigger ingest

    Args:
        file_path : Absolute or relative path to the .zip file on the Kali host.
        poll      : If True (default), wait for ingest to complete and return final status.
        timeout   : Max seconds to wait when poll=True (default 300).

    Returns JSON with:
      - job_id : int
      - status : final job status string (Complete, Failed, Ingesting, etc.)
      - detail : status detail message
    """
    try:
        result = _get_api().file_upload.ingest_file(file_path, poll, timeout)
        return json.dumps(result, indent=2)
    except (BloodhoundAPIError, BloodhoundConnectionError) as e:
        return json.dumps({"error": str(e)})
    except FileNotFoundError as e:
        return json.dumps({"error": f"File not found: {e}"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
