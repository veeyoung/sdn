#!/usr/bin/env python

import requests
from requests.auth import HTTPBasicAuth
import json
import sys
from Tree import TreeNode
import time

ip = "127.0.0.1"
auth = HTTPBasicAuth("karaf", "karaf")


def del_flows_by_appId(controller_ip, appId):
    headers = {
        'Accept': 'application/json',
    }
    get_device_url = 'http://{}:8181/onos/v1/flows/application/{}'.format(controller_ip, appId)
    resp = requests.delete(url=get_device_url, headers=headers, auth=auth)
    return resp.status_code, resp.text


def get_sth(controller_ip, sth):
    headers = { 'Accept': 'application/json' } # 请求的 headers，这是一个字典
    get_url = 'http://{}:8181/onos/v1/{}'.format(controller_ip, sth) # 请求的 URL，这里使用 format 方法以格式化字符串
    resp = requests.get(url=get_url, headers=headers, auth=auth) # 对 URL 的 GET 请求
    return resp.status_code, resp.text # 函数将返回相应的状态码及响应的文本


def disable_fwd(controller_ip, appId, deviceId):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    params = {
        "appId": appId
    }
    flow_rule = {
        "priority": 6,
        "isPermanent": True,
        "flows": [
            {
                "priority": 6,
                "timeout": 0,
                "isPermanent": True,
                "deviceId": deviceId,
                "selector": {
                    "criteria": [
                        {
                            "type": "ETH_TYPE",
                            "ethType": "0x0800"
                        }
                    ]
                },
                "treatment": {
                    "instructions": [
                        {
                            "type": "NOACTION"
                        }
                    ]
                }
            }
        ]
    }

    get_device_url = 'http://{}:8181/onos/v1/flows/{}'.format(controller_ip, deviceId)
    resp = requests.post(url=get_device_url, params=params, headers=headers, auth=auth, data=json.dumps(flow_rule))
    return resp.status_code, resp.text


def add_flows(controller_ip, deviceId, appId, mac_src, mac_dst, sw_port_src, sw_port_dst):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    params = {
        "appId": appId
    }
    data = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": deviceId,
        "treatment": {
            "instructions": [
                {
                    "type": "OUTPUT",
                    "port": sw_port_dst
                }

            ]
        },
        "selector": {
            "criteria": [
                {
                    "type": "ETH_TYPE",
                    "ethType": "0x0800"
                },
                {
                    "type": "IP_PROTO",
                    "protocol": 1
                },
                {
                    "type": "ETH_DST",
                    "mac": mac_dst
                },
                {
                    "type": "ETH_SRC",
                    "mac": mac_src
                },
                {
                    "type": "IN_PORT",
                    "port": sw_port_src
                }
            ]
        }
    }

    get_device_url = 'http://{}:8181/onos/v1/flows/{}'.format(controller_ip, deviceId)
    resp = requests.post(url=get_device_url, params=params, headers=headers, auth=auth, data=json.dumps(data))
    return resp.status_code


def set_multicast_group_table(controller_ip, group_id, output_ports):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    params = {
        "appId": "multicast_routing"  # 用于标识应用程序的唯一ID
    }
    group_data = {
        "groupId": group_id,
        "buckets": [
            {"type": "L2_INTERFACE", "port": port} for port in output_ports
        ]
    }

    group_url = 'http://{}:8181/onos/v1/groups/{}'.format(controller_ip, group_id)
    resp = requests.post(url=group_url, params=params, headers=headers, auth=auth, data=json.dumps(group_data))
    return resp.status_code, resp.text


def dijkstra(graph, start_node):
    unvisited_nodes = {node: sys.maxsize for node in graph}  # 初始化所有节点距离为无穷大
    unvisited_nodes[start_node] = 0  # 起始节点距离为0
    shortest_paths = {start_node: (0, [])}  # 起始节点的路径和距离

    while unvisited_nodes:
        current_node = min(unvisited_nodes, key=unvisited_nodes.get)  # 找到未访问节点中距离最小的节点
        current_distance = unvisited_nodes[current_node]

        for neighbor, distance in graph[current_node].items():
            if neighbor not in unvisited_nodes: continue  # 已访问过的节点跳过
            new_distance = current_distance + distance
            if new_distance < unvisited_nodes[neighbor]:  # 如果找到更短路径，更新
                unvisited_nodes[neighbor] = new_distance
                shortest_paths[neighbor] = (new_distance, shortest_paths[current_node][1] + [current_node])  # 更新路径和距离

        unvisited_nodes.pop(current_node)  # 当前节点已访问过，从未访问节点中删除

    return shortest_paths  # 返回最短路径和距离


def multicast_routing(graph, source, receivers):
    root = TreeNode(source)
    shortest_paths = dijkstra(graph, source)

    for receiver in receivers:
        path_to_receiver = shortest_paths[receiver][1] + [receiver]
        update_multicast_tree(root, path_to_receiver)

    return root


def update_multicast_tree(root, path):
    current_node = root

    for element in path[1:]:
        child = current_node.search_node(element)
        if not child:
            current_node.insert_node(TreeNode(element))
        current_node = current_node.search_node(element)

def are_dicts_equal(dict1, dict2):
    # 判断类型是否为字典
    if not all(isinstance(d, dict) for d in (dict1, dict2)):
        return False
    
    # 判断键集合是否相同
    if set(dict1.keys()) != set(dict2.keys()):
        return False
    
    # 递归比较每个键对应的值
    for key in dict1:
        if key not in dict2:
            return False  # 结构变化，存在一个字典中的键在另一个中不存在
        
        if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            # 递归比较嵌套的字典
            if not are_dicts_equal(dict1[key], dict2[key]):
                return False
        else:
            # 比较非字典类型的值
            if dict1[key] != dict2[key]:
                return False
    
    # 如果所有键对应的值都相等，则字典相同
    return True


if __name__ == '__main__':

    # # 通过appId清空这个App之前下发的所有流表项
    # appId = "org.onosproject.core"
    # status_code, resp = del_flows_by_appId(ip, appId)

    # status_code, resp = get_sth(ip, "devices")
    # devices = json.loads(resp)['devices']
    # devices_id = [i['id'] for i in devices]
    # # # 在所有交换机下发Drop流表项屏蔽fwd转发功能
    # appId = "disable.fwd"
    # for deviceId in devices_id:
    #     status_code, resp = disable_fwd(ip, appId, deviceId)

    last_graph = None
    loop = True
    while loop:
        status_code, resp = get_sth(ip, "links")
        links = json.loads(resp)['links']

        status_code, resp = get_sth(ip, "hosts")
        hosts = json.loads(resp)['hosts']

        status_code, resp = get_sth(ip, "devices")
        devices = json.loads(resp)['devices']
        devices_id = [i['id'] for i in devices]

        if len(links) * len(hosts) * len(devices_id) == 0:
            print("获取拓扑失败!")
            sys.exit(1)

        # 获取拓扑
        graph = dict()
        for link in links:
            if graph.get(link['src']['device']) is not None:
                graph[link['src']['device']][link['dst']['device']] = 1
            else:
                graph[link['src']['device']] = dict()
                graph[link['src']['device']][link['dst']['device']] = 1

        # 判断拓扑是否变化
        if last_graph is not None and are_dicts_equal(last_graph, graph):
            time.sleep(30)
            continue

        appId = "myflow"

        # 删除原来的流表
        for deviceId in devices_id:
            status_code, resp = disable_fwd(ip, appId, deviceId)

        # 通过sanic获取请求
        action_type, actions = sanic_get_post()
         
        if action_type == 'simple_flow':
            hosts = actions
            for i in range(len(hosts) - 1):
                for j in range(i + 1, len(hosts)):
                    start_node = hosts[i]["locations"][0]["elementId"]
                    end_node = hosts[j]["locations"][0]["elementId"]

                    shortest_paths = dijkstra(graph, start_node)
                    path = shortest_paths[end_node][1] + [end_node]

                    sw_port_src = hosts[i]["locations"][0]["port"]

                    for k in range(len(path) - 1):
                        for link in links:
                            if link["src"]["device"] == path[k] and link["dst"]["device"] == path[k + 1]:
                                sw_port_dst = link["src"]["port"]
                                status_code = add_flows('127.0.0.1', path[k], appId, hosts[i]["mac"], hosts[j]["mac"],
                                                        sw_port_src, sw_port_dst)

                                status_code = add_flows('127.0.0.1', path[k], appId, hosts[j]["mac"], hosts[i]["mac"],
                                                        sw_port_dst, sw_port_src)

                                sw_port_src = link["dst"]["port"]
                                break

                    sw_port_dst = hosts[j]["locations"][0]["port"]
                    status_code = add_flows('127.0.0.1', path[-1], appId, hosts[i]["mac"], hosts[j]["mac"], sw_port_src,
                                            sw_port_dst)

                    status_code = add_flows('127.0.0.1', path[-1], appId, hosts[j]["mac"], hosts[i]["mac"], sw_port_dst,
                                            sw_port_src)

        elif action_type == 'group_flow':
            for action in actions:
                root = multicast_routing(graph, "of:0000000000000012", ["of:000000000000000b", "of:0000000000000001"])
                group = root.dfs()
                print(group)

        last_graph = graph
        loop = False