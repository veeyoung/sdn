class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []

    def insert_node(self, child_node):
        self.children.append(child_node)

    def search_node(self, value):
        if not self.children:
            return None
        for node in self.children:
            if node.value == value:
                return node
        return None

    def dfs(self):
        visited = set()
        group = set()
        self._dfs_recursive(self, visited, group)
        return group

    def _dfs_recursive(self, node, visited, group):
        if node is None or node in visited:
            return
        if len(node.children) > 1:
            group.add(node.value)
        visited.add(node)

        for child in node.children:
            self._dfs_recursive(child, visited, group)