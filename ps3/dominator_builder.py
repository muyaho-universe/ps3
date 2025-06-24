import networkx as nx
import matplotlib.pyplot as plt

def build_dominator_tree(cfg, target_func_name):
    # 함수 객체 찾기
    target_func = None
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

    if G.number_of_nodes() == 0:
        print(f"[!] No edges found in function '{target_func_name}'.")
        return None
    
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
    
    return dom_tree

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

    