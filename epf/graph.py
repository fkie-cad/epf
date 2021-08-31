# from typing import Dict, List, Any, Generator
from typing import Any, Generator

import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout


class Graph(object):
    def __init__(self):
        self.g = nx.DiGraph()
        self.root = '_root_'
        self.g.add_node(self.root)

    def visualize(self):
        nx.nx_agraph.write_dot(self.g, 'test.dot')

        # same layout using matplotlib with no labels
        pos = graphviz_layout(self.g, prog='dot')
        nx.draw(self.g, pos, with_labels=True, arrows=True)
        # nx.draw(self.g, with_labels=True)
        plt.show()

    def connect(self, src: Any, dst: Any = None):
        if dst is not None and not self.g.has_node(dst):
            self.g.add_node(dst)
        if not self.g.has_node(src):
            self.g.add_node(src)
        if dst is None:
            dst = src
            src = '_root_'
        if not self.g.has_edge(src, dst):
            self.g.add_edge(src, dst)

    def traverse_from_to(self, from_node: Any, to_node: Any) -> Generator[Any, None, None]:
        for n in nx.shortest_path(self.g, source=from_node, target=to_node)[1:]:
            yield n
