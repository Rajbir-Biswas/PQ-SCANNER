import json
import os


# =========================
# PERSISTENT CRYPTO GRAPH
# =========================

class CryptoGraph:
    def __init__(self, file_path="crypto_graph.json"):
        self.file_path = file_path
        self.nodes = {}
        self.edges = []

        self.load()

    # ---------- LOAD ----------
    def load(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    data = json.load(f)
                    self.nodes = data.get("nodes", {})
                    self.edges = data.get("edges", [])
            except:
                self.nodes = {}
                self.edges = []

    # ---------- SAVE ----------
    def save(self):
        with open(self.file_path, "w") as f:
            json.dump({
                "nodes": self.nodes,
                "edges": self.edges
            }, f, indent=2)

    # ---------- NODE ----------
    def add_node(self, node_type, value):
        key = f"{node_type}:{value}"

        if key not in self.nodes:
            self.nodes[key] = {
                "type": node_type,
                "value": value
            }
            self.save()

        return key

    # ---------- EDGE ----------
    def add_edge(self, from_node, relation, to_node):
        edge = {
            "from": from_node,
            "relation": relation,
            "to": to_node
        }

        if edge not in self.edges:
            self.edges.append(edge)
            self.save()

    # ---------- DEBUG ----------
    def print_graph(self):
        print("\n--- NODES ---")
        for n in self.nodes.values():
            print(n)

        print("\n--- EDGES ---")
        for e in self.edges:
            print(e)


# =========================
# QUERY ENGINE
# =========================

class CryptoGraphQueries:
    def __init__(self, graph):
        self.graph = graph

    # find all domains using algorithm
    def domains_using_algo(self, algo_name):
        algo_name = algo_name.upper()
        domains = []

        for edge in self.graph.edges:
            if edge.get("relation") != "uses":
               continue

        domain_node = self.graph.nodes.get(edge["from"])
        cert_id = edge["to"]

        for e in self.graph.edges:
            if e.get("from") == cert_id and e.get("relation") == "uses_algo":
                algo_node = self.graph.nodes.get(e["to"])

                if algo_node and algo_node["value"].upper() == algo_name:
                    if domain_node:
                        domains.append(domain_node["value"])

        return list(set(domains))
    # find all algorithms
    def all_algorithms(self):
        return [
            n["value"]
            for n in self.graph.nodes.values()
            if n["type"] == "Algorithm"
        ]
