import networkx as nx

def build_dominator_tree(cfg, target_func_name):
    # 함수 객체 찾기
    target_func = None
    nodes = []
    for func in cfg.kb.functions.values():
        if func.name == target_func_name:
            target_func = func
            break

    if target_func is None:
        raise Exception(f"Function '{target_func_name}' not found in CFG!")
    entry_node = target_func.addr
    # print(f"[*] Target function '{target_func_name}' at 0x{entry_node:x}")

    # 4. 함수 내 블록 주소만 추출
    func_block_addrs = set(block.addr for block in target_func.blocks)
    if not func_block_addrs:
        print(f"[!] No blocks found in function '{target_func_name}'.")
        return None
    
    # 5. 전체 CFG에서 함수 블록만으로 서브그래프 생성
    G = nx.DiGraph()
    for src, dst, data in cfg.graph.edges(data=True):
        if src.addr in func_block_addrs and dst.addr in func_block_addrs:
            G.add_edge(src.addr, dst.addr, jumpkind=data['jumpkind'])
            nodes.append({'src': src.addr, 'dst': dst.addr, 'type': data['jumpkind']})
    super_node = merge_nodes(nodes)
    if G.number_of_nodes() == 0:
        print(f"[!] No edges found in function '{target_func_name}'.")
        return nx.DiGraph(), {}
    
    # 6. Immediate dominators 계산
    idoms = nx.immediate_dominators(G, entry_node)
    dom_tree = nx.DiGraph()
    for node, idom in idoms.items():
        if node != idom:
            if G.has_edge(idom, node):
                edge_data = G.get_edge_data(idom, node)
                dom_tree.add_edge(idom, node, **edge_data)
            else:
                dom_tree.add_edge(idom, node)
    
    return dom_tree, super_node


def merge_nodes(nodes):
    parent = {}
    # TODO: CVE-2021-23841 target 병합 실패 이유 찾기
    def find(x):
        while parent.get(x, x) != x:
            x = parent[x]
        return x
    
    def union(x, y):
        x_root = find(x)
        y_root = find(y)
        if x_root != y_root:
            parent[y_root] = x_root
    
    # 1. Ijk_FakeRet edge로 연결된 노드들을 그룹핑
    for item in nodes:
        if item['type'] == 'Ijk_FakeRet':
            union(item['src'], item['dst'])
    
    # 2. 각 노드의 대표(supernode) 구하기
    supernode = {}
    for item in nodes:        
        supernode[item['src']] = find(item['src'])
        supernode[item['dst']] = find(item['dst'])

    return supernode

def print_dom_tree(tree, node, labels, depth=0, visited=None):
    if labels is None:
        labels = {n: hex(n) for n in tree.nodes()}
    if visited is None:
        visited = set()
    print("  " * depth + f"{labels[node]}")
    visited.add(node)
    for child in tree.successors(node):
        if child not in visited:
            print_dom_tree(tree, child, labels, depth + 1, visited)

    