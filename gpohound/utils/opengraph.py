"""
BloodHound OpenGraph ingest builder for GPOHound.

This module is the single place where GPOHound turns its GPO dump/analysis/
enrichment results into a BloodHound CE v8+ OpenGraph ingest file, using the
`bhopengraph` library (https://github.com/p0dalirius/bhopengraph).

It replaces the previous approach of writing directly into a live Neo4j/
BloodHound database over the Bolt protocol (APOC procedures, `MERGE` queries,
...). GPOHound now only *reads* from BloodHound (or an offline LDAP dump) to
resolve trustees/OUs/computers, and always *writes* by producing a portable
OpenGraph JSON file bundled in a zip that can be uploaded through BloodHound
CE's "File Ingest" page (Administration > Data Collection > File Ingest) or
its `/api/v2/ingest` endpoint. No live database connection or APOC plugin is
required to generate the ingest data.

Two kinds of nodes are produced:

- Standalone GPOHound nodes (Domain/GPO/OU) used to represent GPO
  applicability, identified by GPOHound-specific ids (e.g. "OU:<dn>").
- Stub nodes that mirror existing Active Directory objects (trustees,
  computers, GPOs), identified by their objectid/SID. These carry only
  `properties.objectid` (and, for computer property enrichment, the actual
  new properties). BloodHound deduplicates nodes on `properties.objectid`,
  so ingesting one of these stubs merges properties/edges onto the existing
  AD object collected by SharpHound instead of creating a duplicate node.
  See https://bloodhound.specterops.io/opengraph/best-practices
"""

import json
import logging
import zipfile
from pathlib import Path

from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties

# Generic fallback kind used for AD stub nodes (trustees) whose exact type
# (User/Group/Computer) isn't known at the point they're referenced by an edge.
BASE_KIND = "Base"


def sanitize_property(value):
    """
    Coerce a value into something the OpenGraph schema accepts as a node/edge
    property: a primitive (str, int, float, bool) or a homogeneous array of
    primitives. Nested dict/list structures are flattened to a JSON string as
    a last resort so nothing is silently lost.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, list):
        # Only keep the list as-is if every element is already a scalar
        if all(isinstance(item, (str, int, float, bool)) or item is None for item in value):
            # Filter out Nones since OpenGraph arrays must be homogeneous primitives
            cleaned = [item for item in value if item is not None]
            return cleaned if cleaned else json.dumps(value, default=str)
        return json.dumps(value, default=str)

    if isinstance(value, dict):
        return json.dumps(value, default=str)

    return str(value)


class GPOHoundGraph:
    """
    Accumulates GPOHound findings into a bhopengraph OpenGraph instance and
    exports it as a BloodHound OpenGraph ingest zip.
    """

    def __init__(self, source_kind="GPOHound"):
        self.graph = OpenGraph(source_kind=source_kind)

        # Human readable summary of what was added, used for CLI printing.
        # {"Memberships": {group: {trustee: {computer, ...}}}, ...}
        self.summary = {"Memberships": {}, "Privilege Rights": {}, "Properties": {}}

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    @property
    def node_count(self):
        return len(self.graph.nodes)

    @property
    def edge_count(self):
        return len(self.graph.edges)

    def _upsert_node(self, node_id, kinds, properties):
        """
        Create a node, or merge new kinds/properties onto one already added
        under the same id (bhopengraph's own add_node() is create-only and
        silently no-ops on a collision, which would drop data here).
        """

        clean_props = {key: sanitize_property(value) for key, value in properties.items() if value is not None}

        existing = self.graph.nodes.get(node_id)
        if existing:
            for key, value in clean_props.items():
                existing.set_property(key, value)
            for kind in kinds:
                existing.add_kind(kind)
            return existing

        node = Node(id=node_id, kinds=list(kinds), properties=Properties(**clean_props))
        self.graph.add_node(node)
        return node

    def _add_stub_node(self, objectid, kind):
        """
        Ensure a minimal placeholder node exists for an AD object (trustee or
        computer) identified by its SID, so that edges referencing it validate
        locally. Carries only `objectid`, which is BloodHound's own dedup key:
        on ingest this merges onto the existing AD node instead of creating a
        new one.
        """

        return self._upsert_node(objectid, [kind], {"objectid": objectid})

    def _add_edge(self, start_id, end_id, kind, properties=None):
        props = None
        if properties:
            clean = {key: sanitize_property(value) for key, value in properties.items() if value is not None}
            props = Properties(**clean) if clean else None

        edge = Edge(start_id, end_id, kind, properties=props)
        return self.graph.add_edge(edge)

    # ------------------------------------------------------------------
    # Dump / analysis export (GPOHound's own Domain/GPO/OU nodes)
    # ------------------------------------------------------------------

    def _flatten_findings(self, node, gpo_props, findings):
        """
        Walk an analysis/dump sub-tree looking for the "analysis" /
        "bloodhound_property" pattern used by every GPOHound analyser
        (Registry, Privilege Rights, Memberships, GPP Password, ...) and pull
        that information into flat GPO node properties instead of the nested
        objects the OpenGraph schema rejects.
        """

        if isinstance(node, dict):
            if "analysis" in node and node.get("analysis"):
                finding = str(node["analysis"])
                regkey = node.get("regkey")
                if regkey:
                    finding = f"{finding} ({regkey})"
                findings.append(finding)

                for key, value in self._normalise_bloodhound_property(node).items():
                    if key:
                        gpo_props[str(key)] = sanitize_property(value)

            for key, value in node.items():
                if key in ("analysis", "bloodhound_property", "references"):
                    continue
                self._flatten_findings(value, gpo_props, findings)

        elif isinstance(node, list):
            for item in node:
                self._flatten_findings(item, gpo_props, findings)

    @staticmethod
    def _normalise_bloodhound_property(node):
        """
        GPOHound analysers set `bloodhound_property` either as a dict
        ({property_name: value}) or as a bare string (property_name), in
        which case the analysed value itself is used.
        """

        bloodhound_property = node.get("bloodhound_property") if isinstance(node, dict) else None
        if not bloodhound_property:
            return {}

        if isinstance(bloodhound_property, dict):
            return dict(bloodhound_property)

        return {str(bloodhound_property): node.get("value", True)}

    def add_gpo_dump_data(self, data):
        """
        Ingest GPOHound "dump"/"analysis" output (nested {domain: {guid:
        {...}}}) as Domain/GPO/OU OpenGraph nodes, linked by GPOAppliesTo
        edges. Can be called multiple times (e.g. once for dump, once for
        analysis) on the same graph to merge datasets.
        """

        for domain, gpos in (data or {}).items():
            domain_id = f"DOMAIN:{domain}"
            self._upsert_node(domain_id, ["Domain"], {"name": domain})

            if not isinstance(gpos, dict):
                continue

            for gpo_guid, gpo_info in gpos.items():
                if not isinstance(gpo_info, dict):
                    continue

                gpo_id = f"{gpo_guid}@{domain}"
                gpo_props = {
                    "name": gpo_info.get("GPO Name", gpo_guid),
                    "guid": gpo_guid,
                    "domain": domain,
                }

                findings = []
                affected_ous = gpo_info.get("Affected OUs")

                for key, value in gpo_info.items():
                    if key in ("GPO Name", "Affected OUs"):
                        continue
                    self._flatten_findings(value, gpo_props, findings)

                if findings:
                    gpo_props["findings"] = findings

                self._upsert_node(gpo_id, ["GPO"], gpo_props)

                if isinstance(affected_ous, dict) and affected_ous:
                    for ou_dn, ou_info in affected_ous.items():
                        ou_id = f"OU:{ou_dn}"
                        ou_props = {"name": ou_dn, "distinguishedname": ou_dn}
                        if isinstance(ou_info, dict):
                            for extra_key, extra_value in ou_info.items():
                                ou_props[f"affected_{extra_key}".lower()] = sanitize_property(extra_value)

                        self._upsert_node(ou_id, ["OU"], ou_props)
                        self._add_edge(gpo_id, ou_id, "GPOAppliesTo")
                else:
                    # Fall back to linking the GPO directly to its domain when
                    # no OU-level impact data is available
                    self._add_edge(gpo_id, domain_id, "GPOAppliesTo")

    # ------------------------------------------------------------------
    # BloodHound enrichment (relationships/properties derived from GPOs)
    # ------------------------------------------------------------------

    @staticmethod
    def _computers_in_ous(ad_utils, ou_ids, domain_sid):
        """
        Resolve the affected OUs to their actual computer objects (dedup'd by
        SID), via a live BloodHound read connection or an offline LDAP dump.
        """

        computers = {}
        for ou_id in ou_ids:
            found = ad_utils.get_machines_in_ou(ou_id, domain_sid) or []
            for computer in found:
                objectid = computer.get("objectid")
                if objectid:
                    computers.setdefault(objectid.upper(), computer)

        return list(computers.values())

    def _add_trustee_computer_relationship(
        self, trustee_sid, trustee_name, computer, edge_kind, group_sid, group_name, ingestor
    ):
        computer_sid = computer.get("objectid")
        if not computer_sid:
            return

        computer_sid = computer_sid.upper()
        computer_name = computer.get("samaccountname")

        self._add_stub_node(trustee_sid, BASE_KIND)
        self._add_stub_node(computer_sid, "Computer")
        self._add_edge(trustee_sid, computer_sid, edge_kind, {"gpohound": True})

        if ingestor == "bh-ce" and group_sid and group_name:
            try:
                self.add_local_group_relationship(trustee_sid, computer_sid, computer_name, group_sid, group_name)
            except Exception as error:
                logging.debug(f"Error adding local group relationship for BloodHound CE style ingest: {error}")

        self.summary["Memberships"].setdefault(group_name, {}).setdefault(trustee_name or trustee_sid, set()).add(
            computer_name
        )

    def add_local_group_relationship(self, trustee_sid, computer_sid, computer_name, group_sid, group_name):
        """
        Model a trustee's membership of a computer's local group using an
        `ADLocalGroup` node, mirroring SharpHound CE's own collection style:
        Trustee -[MemberOfLocalGroup]-> ADLocalGroup -[LocalToComputer]-> Computer

        Each computer gets its own local group node, with an id in the format
        COMPUTER_SID-GROUP_RID and a name following SharpHound's
        "GROUPNAME@COMPUTERNAME" convention.
        """

        group_rid = group_sid.split("-")[-1]
        local_group_id = f"{computer_sid}-{group_rid}"
        display_computer_name = computer_name.rstrip("$") if computer_name else computer_name
        display_name = f"{group_name.upper()}@{display_computer_name}" if display_computer_name else group_name.upper()

        self._upsert_node(
            local_group_id,
            ["ADLocalGroup"],
            {"objectid": local_group_id, "name": display_name},
        )

        self._add_edge(trustee_sid, local_group_id, "MemberOfLocalGroup")
        self._add_edge(local_group_id, computer_sid, "LocalToComputer")

    def add_computer_property(self, computer_sid, computer_name, key, value):
        """
        Merge a new property onto an existing Computer AD object (e.g. a
        registry setting exposing a VNC password, weak NTLM configuration,
        ...), matched by SID.
        """

        computer_sid = computer_sid.upper()
        properties = {"objectid": computer_sid, key: value}
        if computer_name:
            properties["samaccountname"] = computer_name

        self._upsert_node(computer_sid, ["Computer"], properties)

        self.summary["Properties"].setdefault(str(key), {}).setdefault(str(sanitize_property(value)), set()).add(
            computer_name
        )

    def add_enrichment(self, analyses, domain, domain_sid, ad_utils, ingestor):
        """
        Build OpenGraph nodes/edges from GPOHound's GPO analysis output.

        `analyses` is a list of {"analysis": <GPO analysis dict>, "affected":
        [ou_objectid, ...]} entries, as produced by GPOHoundCore.

        `ingestor` selects the relationship modeling style:
          - "bh-legacy": a single direct edge between the trustee and each
            affected computer (fast, matches BloodHound's classic edges).
          - "bh-ce": additionally models the relationship through a
            synthetic ADLocalGroup node, matching how SharpHound CE collects
            local group membership.
        """

        for data in analyses:
            analysed_gpo = data["analysis"]
            ou_ids = data["affected"]

            computers = self._computers_in_ous(ad_utils, ou_ids, domain_sid)
            if not computers:
                continue

            # Local group memberships applied to computers
            if "Memberships" in analysed_gpo:
                for analysed_settings in analysed_gpo["Memberships"].values():
                    for group in analysed_settings:
                        group_sid = group.get("sid")
                        group_name = group.get("name")
                        edge = group.get("edge")

                        if not (group_sid and edge):
                            continue

                        if "Members" in group:
                            for member in group["Members"]:
                                sid = member.get("sid")
                                if not sid:
                                    continue
                                for computer in computers:
                                    self._add_trustee_computer_relationship(
                                        sid.upper(),
                                        member.get("name"),
                                        computer,
                                        edge,
                                        group_sid,
                                        group_name,
                                        ingestor,
                                    )

                        if "EnvMembers" in group:
                            for entry in group["EnvMembers"]:
                                sid = entry.get("sid")
                                computer_sid = entry.get("computer_sid")
                                if not (sid and computer_sid):
                                    continue

                                computer = {
                                    "objectid": computer_sid,
                                    "samaccountname": entry.get("computer_name"),
                                }
                                self._add_trustee_computer_relationship(
                                    sid.upper(), entry.get("name"), computer, edge, group_sid, group_name, ingestor
                                )

            # Interesting properties added to computers
            if "Registry" in analysed_gpo:
                for analysed_settings in analysed_gpo["Registry"].values():
                    for registry in analysed_settings:
                        for key, value in self._normalise_bloodhound_property(registry).items():
                            for computer in computers:
                                self.add_computer_property(
                                    computer.get("objectid"), computer.get("samaccountname"), key, value
                                )

            # Relationships to computers where trustees can escalate privileges
            if "Privilege Rights" in analysed_gpo:
                for analysed_settings in analysed_gpo["Privilege Rights"].values():
                    for privilege, entry in analysed_settings.items():
                        edge = entry.get("edge")
                        if not edge:
                            continue

                        for trustee in entry.get("trustees", []):
                            sid = trustee.get("sid")
                            if not sid:
                                continue

                            sid = sid.upper()
                            for computer in computers:
                                computer_sid = computer.get("objectid")
                                if not computer_sid:
                                    continue

                                computer_sid = computer_sid.upper()
                                computer_name = computer.get("samaccountname")

                                self._add_stub_node(sid, BASE_KIND)
                                self._add_stub_node(computer_sid, "Computer")
                                self._add_edge(sid, computer_sid, edge, {"gpohound": True})

                                self.summary["Privilege Rights"].setdefault(privilege, {}).setdefault(
                                    trustee.get("name") or sid, set()
                                ).add(computer_name)

    def get_summary(self):
        """
        JSON-serializable version of the enrichment summary (sets of computer
        names turned into sorted lists).
        """

        def _convert(value):
            if isinstance(value, dict):
                return {str(k): _convert(v) for k, v in value.items()}
            if isinstance(value, set):
                return sorted(name for name in value if name)
            return value

        return {section: _convert(content) for section, content in self.summary.items() if content}

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, indent=2):
        return self.graph.export_json(include_metadata=True, indent=indent)

    def export_zip(self, output_dir, zip_name, inner_filename="gpohound_opengraph.json"):
        """
        Write the graph as a BloodHound OpenGraph ingest zip:
        {output_dir}/{zip_name}, containing a single {inner_filename} with
        {"metadata": {...}, "graph": {"nodes": [...], "edges": [...]}}.
        """

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        if not zip_name.endswith(".zip"):
            zip_name += ".zip"

        zip_path = output_path / zip_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner_filename, self.export_json())

        return zip_path
