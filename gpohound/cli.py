import json
import zipfile
from pathlib import Path

from itertools import zip_longest

from rich.console import Console
from rich.json import JSON
from rich.tree import Tree
from rich.table import Table
from rich.console import Console

from gpohound.utils.utils import search_keys_values
from gpohound.utils.opengraph import GPOHoundGraph


console = Console(highlight=False)


class GPOHoundCLI:
    """
    Class for printing results to the CLI
    """

    def __init__(self, gpohound_core, json_output=False, output_dir=None, zip_name=None, bloodhound_format=False):
        self.gpohound_core = gpohound_core
        self.print_json = json_output
        self.output_dir = output_dir
        self.zip_name = zip_name
        self.bloodhound_format = bloodhound_format

    def save_json_zip(self, data, output_dir, zip_name, inner_filename="gpohound_output.json"):
        """
        Write data as JSON and package it into a zip file at output_dir/zip_name
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        zip_path = output_path / zip_name
        json_bytes = json.dumps(data, indent=4, default=str).encode("utf-8")

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner_filename, json_bytes)

        console.print(f"Output written to {zip_path}")

    def save_bundle_zip(self, bundle, output_dir, zip_name):
        """
        Write multiple named JSON entries into a single zip file
        bundle: dict of {filename: data}
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        zip_path = output_path / zip_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for filename, data in bundle.items():
                json_bytes = json.dumps(data, indent=4, default=str).encode("utf-8")
                zf.writestr(filename, json_bytes)

        console.print(f"Output written to {zip_path}")

    def build_bloodhound_opengraph(self, data, graph=None):
        """
        Convert GPOHound "dump"/"analysis" output (nested {domain: {guid: {...}}})
        into a bhopengraph-backed GPOHoundGraph. Accepts an existing `graph`
        so multiple datasets (e.g. dump + analysis) can be merged into one
        before being exported.
        """

        if graph is None:
            graph = GPOHoundGraph(source_kind="GPOHound")

        graph.add_gpo_dump_data(data)
        return graph

    def write_bloodhound_zip(self, graph, output_dir, zip_name):
        """
        Export a GPOHoundGraph to a BloodHound CE v8+ OpenGraph ingest zip.
        """

        zip_path = graph.export_zip(output_dir, zip_name, inner_filename="gpohound_data.json")
        console.print(f"BloodHound OpenGraph output written to {zip_path}")

    def save_bloodhound_zip(self, data, output_dir, zip_name):
        """
        Convenience wrapper: build the OpenGraph for a single dataset and
        write it straight to a zip.
        """

        graph = self.build_bloodhound_opengraph(data)
        self.write_bloodhound_zip(graph, output_dir, zip_name)

    def parse_gpo_file(self, file_path):
        """
        Dump a single GPO file
        """

        policy = self.gpohound_core.parse_file(file_path)

        if policy:
            if self.print_json:
                console.print(JSON.from_data(policy, indent=4))
            else:
                self.print_dict_as_tree("Parse results", policy)
        else:
            console.print("Error during parsing or empty GPO file")

    def parse_policies(self, domains, guids, affected=False):
        """
        Parse the GPOs
        """

        parsed_policies = self.gpohound_core.parse_policies(domains, guids, affected)

        if parsed_policies:
            return parsed_policies

        console.print("No GPOs were found...")
        return None

    def list_gpos(self, domains=None, guids=None):
        """
        Print the GPOs list
        """

        parsed_policies = self.gpohound_core.list_policies(domains, guids)
        if parsed_policies:
            if self.print_json:
                console.print(JSON.from_data(parsed_policies, indent=4))
            else:
                self.print_dict_as_tree("GPOs", parsed_policies)
        else:
            console.print("No GPOs to list for the given filter(s)...")

    def dump_gpos_settings(self, domains=None, guids=None, affected=False):
        """
        Dumps the GPOs settings
        """

        parsed_policies = self.parse_policies(domains, guids, affected)

        if not parsed_policies:
            return

        if self.output_dir:
            if self.bloodhound_format:
                self.save_bloodhound_zip(parsed_policies, self.output_dir, self.zip_name)
            else:
                self.save_json_zip(parsed_policies, self.output_dir, self.zip_name, "dump.json")
        elif self.print_json:
            console.print(JSON.from_data(parsed_policies, indent=4))
        else:
            self.print_dict_as_tree("GPOs", parsed_policies)

    def search_gpo_settings(self, domains=None, guids=None, search=None, show=None):
        """
        Regex search in the parsed policies
        """

        parsed_policies = self.parse_policies(domains, guids)
        if not parsed_policies:
            return

        search_results = search_keys_values(parsed_policies, search, show)
        if search_results:
            if self.print_json:
                console.print(JSON.from_data(search_results))
            else:
                self.print_dict_as_tree("Search results", search_results)
        else:
            console.print("No GPOs search results were found for the given filter(s)...")

    def inheritance_on_object(self, object, type="ou"):
        """
        Print the ordered GPOs applied on an object
        """

        found_ou = self.gpohound_core.get_ou_object(object, type)
        if not found_ou:
            return None, None, None

        domain, ou_ordered_gpos = self.gpohound_core.get_gpos_on_ou(found_ou)
        if not ou_ordered_gpos:
            return None, None, None

        return domain, found_ou, ou_ordered_gpos

    def dump_gpo_applied_on_object(self, object, type="ou", affected=False):
        """
        Dumps GPOs applied on an object
        """

        domain, found_ou, ou_ordered_gpos = self.inheritance_on_object(object, type)

        if domain and found_ou and ou_ordered_gpos:
            ou_gpo_dump = self.gpohound_core.dump_ou_gpos_settings(domain, ou_ordered_gpos, affected)

            if not ou_gpo_dump:
                console.print("No GPOs were found for the given filter(s)...")
                return

            output = {found_ou.get("distinguishedname"): ou_gpo_dump}
            if self.print_json:
                console.print(JSON.from_data(output, indent=4))
            else:
                self.print_dict_as_tree("GPO Precedence (first GPO is applied last)", output)

    def list_gpos_applied_on_object(self, object, type="ou"):
        """
        Print the GPOs list applied on an object
        """

        _, found_ou, ou_ordered_gpos = self.inheritance_on_object(object, type)
        if not ou_ordered_gpos or not found_ou:
            console.print("No OU was found for the given object")
            return

        gpo_list = self.gpohound_core.list_ou_gpos(ou_ordered_gpos)
        if not gpo_list:
            console.print("No GPOs were found for the given filter(s)...")
            return

        output = {found_ou.get("distinguishedname"): gpo_list}
        if self.print_json:
            console.print(JSON.from_data(output, indent=4))
        else:
            self.print_dict_as_tree("GPO Precedence (first GPO is applied last)", output)

    def analyse_gpos_applied_on_object(self, object, type="ou", objects=None, affected=False):
        """
        Print the analysis of GPOs applied on an object
        """

        domain, found_ou, ou_ordered_gpos = self.inheritance_on_object(object, type)
        if domain and found_ou and ou_ordered_gpos:
            domain_sid = found_ou.get("domainsid")

            ou_analysis = self.gpohound_core.analyse_ou_gpos(domain, domain_sid, ou_ordered_gpos, objects, affected)
            if not ou_analysis:
                console.print("No results were found for the specified settings...")
                return

            if self.print_json:
                console.print(JSON.from_data(ou_analysis, indent=4))
            else:
                self.print_analysed(ou_analysis)
        else:
            console.print("No results were found for the specified settings...")

    def analyse_gpos(self, domains=None, guids=None, objects=None, affected=False):
        """
        Print the analysis of the SYSVOL's GPOs
        """

        output_analysis = self.gpohound_core.analyse_all_gpos(domains, guids, objects, affected)
        if not output_analysis:
            console.print("No results were found for the specified settings...")
            return

        if self.output_dir:
            if self.bloodhound_format:
                self.save_bloodhound_zip(output_analysis, self.output_dir, self.zip_name)
            else:
                self.save_json_zip(output_analysis, self.output_dir, self.zip_name, "analysis.json")
        elif self.print_json:
            console.print(JSON.from_data(output_analysis, indent=4))
        else:
            self.print_analysed(output_analysis)

    def enrich_bh(self, ingestor, domains=None, guids=None):
        """
        Build the BloodHound OpenGraph enrichment data (relationships and
        properties derived from GPOs), write it to a zip, and print a summary.
        """

        graph = self.gpohound_core.enrich_bloodhound(ingestor, domains, guids)
        if not graph or not (graph.node_count or graph.edge_count):
            console.print("Empty enrichment results...")
            return

        output_dir = self.output_dir or "."
        zip_name = self.zip_name or "gpohound_enrich.zip"

        zip_path = graph.export_zip(output_dir, zip_name, inner_filename="gpohound_enrich.json")
        console.print(f"BloodHound OpenGraph enrichment written to {zip_path}")

        enrichment_output = graph.get_summary()
        if not enrichment_output:
            return

        if self.print_json:
            console.print(JSON.from_data(enrichment_output, indent=4))
        else:
            self.print_enriched(enrichment_output)

    def table_output_width(self):
        """
        Get the current terminal width for table output
        """

        table_width = Console().size.width

        if table_width - 20 > 1:
            table_width -= 20

        return table_width

    def print_dict_as_tree(self, label, dictionary):
        """
        Recursively builds and prints a tree representation of the nested dictionary.
        """

        def dict_to_tree(data, parent, depth=0):
            for key, value in data.items():
                if key == "Affected OUs":

                    node = parent.add("[bold blue]Affected OUs [/bold blue]")
                    table_ou = Table(show_lines=True)
                    table_ou.add_column("OUs")
                    table_ou.add_column("Users", justify="center")
                    table_ou.add_column("Computers", justify="center")

                    for ou, trustees in value.items():
                        users = len(trustees.get("Users"))
                        computers = len(trustees.get("Computers"))
                        table_ou.add_row(ou, str(users), str(computers))

                    node.add(table_ou)

                elif isinstance(value, list):
                    list_tree = None

                    for i, item in enumerate(value):

                        if isinstance(item, dict):
                            item_tree = parent.add(f"[bold blue]{key} {i+1} [/bold blue]")
                            dict_to_tree(item, item_tree, depth + 1)
                        else:
                            if not list_tree:
                                if depth == 0:
                                    list_tree = parent.add(f"[bold red]{key} [/bold red]")
                                else:
                                    list_tree = parent.add(f"[bold blue]{key} [/bold blue]")
                            list_tree.add(f"[bold]{item} [/bold]")

                elif isinstance(value, dict):

                    if depth == 0:
                        node = parent.add(f"[bold red]{key} [/bold red]")
                    elif depth == 1:
                        key = key.split(":", 1)
                        if len(key) == 2:
                            node = parent.add(f"[bold blue]{key[0]} [/bold blue]:[bold cyan]{key[1]} [/bold cyan]")
                        else:
                            node = parent.add(f"[bold blue]{key[0]} [/bold blue]")
                    else:
                        node = parent.add(f"[bold blue]{key} [/bold blue]")
                    dict_to_tree(value, node, depth + 1)

                else:
                    parent.add(f"[bold blue]{key} [/bold blue]: [bold]{value} [/bold]")

        tree = Tree(label=f"[bold]{label} [/bold]")
        dict_to_tree(dictionary, tree)
        console = Console()
        console.print(tree)

    def print_analysed(self, analysed):
        """
        Print analysis and builds tables for each settings.
        """

        def analysed_to_tree(data, parent, depth=0):
            for key, value in data.items():

                if key == "Affected OUs":

                    node = parent.add("[bold blue]Affected OUs [/bold blue]")
                    table_ou = Table(show_lines=True)
                    table_ou.add_column("OUs")
                    table_ou.add_column("Users", justify="center")
                    table_ou.add_column("Computers", justify="center")

                    for ou, trustees in value.items():
                        users = len(trustees.get("Users"))
                        computers = len(trustees.get("Computers"))
                        table_ou.add_row(ou, str(users), str(computers))

                    node.add(table_ou)

                elif key == "Registry":

                    registry_node = parent.add("[bold blue]Registries [/bold blue]")

                    for policy_type, gpo_group in value.items():

                        node = registry_node.add(f"[bold blue]{policy_type} [/bold blue]")

                        for registry in gpo_group:
                            table_registry = Table(show_lines=True, width=int(self.table_output_width() * 0.75))
                            table_registry.add_column("Analysis", width=12, justify="center", style="bold")
                            table_registry.add_column(registry.get("analysis"), ratio=1, overflow="fold")

                            table_registry.add_row("RegKey", registry.get("regkey"))
                            table_registry.add_row("Value", registry.get("value"))

                            if "VNC Password" in registry:
                                table_registry.add_row("VNC Password", registry.get("VNC Password"))

                            node.add(table_registry)

                elif key == "Privilege Rights":

                    priv_node = parent.add("[bold blue]Privilege Rights [/bold blue]")

                    for policy_type, data in value.items():

                        node = priv_node.add(f"[bold blue]{policy_type} [/bold blue]")

                        for priv_data in data.values():

                            # Tables for trustees
                            table_trustees = Table(show_lines=True, expand=True)
                            table_trustees.add_column("SID", ratio=10, justify="center")
                            table_trustees.add_column("Name", ratio=8, justify="center")

                            for member in priv_data.get("trustees", []):
                                table_trustees.add_row(member.get("sid"), member.get("name"))

                            # Table for analysis
                            table_privilege = Table(show_lines=True, width=int(self.table_output_width() * 0.79))
                            table_privilege.add_column("Analysis", width=10, justify="center", style="bold")
                            table_privilege.add_column(priv_data.get("analysis"), ratio=1, overflow="fold")

                            # Add values
                            table_privilege.add_row("Trustees", table_trustees)
                            table_privilege.add_row("References", priv_data.get("references"))

                            node.add(table_privilege)

                elif key == "Memberships":

                    groups_node = parent.add("[bold blue]Groups [/bold blue]")

                    for policy_type, gpo_group in value.items():

                        node = groups_node.add(f"[bold blue]{policy_type} [/bold blue]")

                        for group in gpo_group:

                            # Tables for members
                            table_members = Table(show_lines=True, expand=True)
                            table_members.add_column("SID", ratio=10, justify="center")
                            table_members.add_column("Trustee", ratio=8, justify="center")

                            for member in group.get("Members", []):
                                table_members.add_row(member.get("sid"), member.get("name"))

                            # Table for analysis
                            table_group = Table(show_lines=True, width=int(self.table_output_width() * 0.85))
                            table_group.add_column("Analysis", width=10, justify="center", style="bold")
                            table_group.add_column(group.get("analysis"), ratio=1, overflow="fold")

                            # Add values
                            if group.get("Members"):
                                table_group.add_row("Members", table_members)

                            if group.get("EnvMembers"):
                                table_single = Table(show_lines=True, expand=True)
                                table_single.add_column("SID", ratio=10, justify="center")
                                table_single.add_column("Trustee and Computer", ratio=8, justify="center")

                                for member in group.get("EnvMembers", []):
                                    table_single.add_row(
                                        member["sid"], f"{member['name']} on {member['computer_name']}"
                                    )

                                table_group.add_row("Env. Members", table_single)

                            # Add values
                            if group.get("Hijackable"):
                                table_hijack = Table(show_lines=True, expand=True)
                                table_hijack.add_column("20 chars or less", ratio=10, justify="center")
                                table_hijack.add_column("More than 20 chars", ratio=8, justify="center")

                                hijackable_list = list(
                                    zip_longest(group["Hijackable"]["lte_20"], group["Hijackable"]["gt_20"])
                                )
                                for row in hijackable_list:
                                    table_hijack.add_row(row[0], row[1])
                                table_group.add_row("Hijackable", table_hijack)

                            table_group.add_row("References", group.get("references"))

                            node.add(table_group)

                elif key == "GPP Password":

                    gpppassword_node = parent.add("[bold blue]GPP Password [/bold blue]")

                    for path, passwords in value.items():

                        node = gpppassword_node.add(f"[bold blue]{path} [/bold blue]")

                        table_password = Table(show_lines=True, width=int(self.table_output_width() * 0.79))
                        table_password.add_column("Decrypted", width=10, justify="center", style="bold")
                        table_password.add_column(passwords.get("decrypted"), ratio=1, overflow="fold")
                        table_password.add_row("Encrypted", passwords.get("encrypted"))

                        node.add(table_password)

                elif isinstance(value, list):
                    list_tree = None
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            item_tree = parent.add(f"[bold blue]{key} {i+1} [/bold blue]")
                            analysed_to_tree(item, item_tree, depth + 1)
                        else:
                            if not list_tree:
                                list_tree = parent.add(f"[bold blue]{key} [/bold blue]")
                            list_tree.add(f"[bold]{item} [/bold]")

                elif isinstance(value, dict):
                    if depth == 0:
                        node = parent.add(f"[bold red]{key} [/bold red]")  # Domain Name
                    else:
                        node = parent.add(f"[bold blue]{key} [/bold blue]")  # Normal Key
                    analysed_to_tree(value, node, depth + 1)
                else:
                    parent.add(f"[bold blue]{key} [/bold blue]: [bold]{value} [/bold]")  # Data (leaf nodes)

        tree = Tree("[bold]GPO Analysis [/bold]")
        analysed_to_tree(analysed, tree, depth=0)
        console = Console()
        console.print(tree)

    def print_enriched(self, output_enrichment):
        """
        Print enrichement results
        """

        def enriched_to_tree(data, parent, depth=0):
            for key, value in data.items():
                if value:
                    if key == "Properties":
                        properties_table = Table(show_lines=True, width=int(self.table_output_width() * 0.79))
                        properties_table.add_column("Key", ratio=5, justify="center")
                        properties_table.add_column("Value", ratio=5, justify="center")
                        properties_table.add_column("Number of computers", ratio=4, justify="center")

                        rows = [
                            (prop_key, prop_value, machines)
                            for prop_key, prop_values in value.items()
                            for prop_value, machines in prop_values.items()
                        ]
                        rows.sort(key=lambda row: len(row[2]), reverse=True)

                        for prop_key, prop_value, machines in rows:
                            properties_table.add_row(prop_key, str(prop_value), str(len(machines)))

                        properties_node = parent.add("[bold blue]Properties [/bold blue]").add(
                            "[bold]Interesting properties added to computers [/bold]"
                        )
                        properties_node.add(properties_table)

                    elif key == "Privilege Rights":
                        privileges_node = parent.add("[bold blue]Privilege Rights [/bold blue]")
                        for privilege, trustees in value.items():
                            privilege_table = Table(show_lines=True, width=int(self.table_output_width() * 0.79))
                            privilege_table.add_column("Trustee", ratio=10, justify="center")
                            privilege_table.add_column("Number of computers", ratio=4, justify="center")

                            sorted_trustees = dict(
                                sorted(trustees.items(), key=lambda item: len(item[1]), reverse=True)
                            )
                            for trustee, machines in sorted_trustees.items():
                                privilege_table.add_row(trustee, str(len(machines)))

                            privilege_node = privileges_node.add(
                                f"[bold]Trustee(s) that can escalate privilieges with : {privilege} [/bold]"
                            )
                            privilege_node.add(privilege_table)

                    elif key == "Memberships":
                        memberships_node = parent.add("[bold blue]Memberships [/bold blue]")

                        for membership, trustees in value.items():

                            membership_table = Table(show_lines=True, width=int(self.table_output_width() * 0.79))
                            membership_table.add_column("Trustee", ratio=10, justify="center")
                            membership_table.add_column("Number of computers", ratio=4, justify="center")

                            sorted_trustees = dict(
                                sorted(trustees.items(), key=lambda item: len(item[1]), reverse=True)
                            )
                            for trustee, machines in sorted_trustees.items():
                                membership_table.add_row(trustee, str(len(machines)))

                            membership_node = memberships_node.add(
                                f"[bold]Trustee(s) added to the local group : {membership} [/bold]"
                            )
                            membership_node.add(membership_table)

                    elif isinstance(value, list):
                        list_tree = None
                        for i, item in enumerate(value):
                            if isinstance(item, dict):
                                item_tree = parent.add(f"[bold blue]{key} {i+1} [/bold blue]")
                                enriched_to_tree(item, item_tree, depth + 1)
                            else:
                                if not list_tree:
                                    list_tree = parent.add(f"[bold blue]{key} [/bold blue]")
                                list_tree.add(f"[bold]{item} [/bold]")

                    elif isinstance(value, dict):
                        if depth == 0:
                            node = parent.add(f"[bold red]{key} [/bold red]")  # Domain Name
                        else:
                            node = parent.add(f"[bold blue]{key} [/bold blue]")  # Normal Key
                        enriched_to_tree(value, node, depth + 1)

        tree = Tree("[bold]Enrichement results [/bold]")
        enriched_to_tree(output_enrichment, tree, depth=0)
        console = Console()
        console.print(tree)