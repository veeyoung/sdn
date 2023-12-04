#!/usr/bin/env python
#coding: utf-8
import requests
from requests.auth import HTTPBasicAuth
import json
import sys

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


if __name__ == '__main__':
    status_code, resp = get_sth(ip, "links")
    links = json.loads(resp)['links']

    status_code, resp = get_sth(ip, "hosts")
    hosts = json.loads(resp)['hosts']

    status_code, resp = get_sth(ip, "devices")
    devices = json.loads(resp)['devices']
    devices_id = [i['id'] for i in devices]

    if len(links)*len(hosts)*len(devices_id) == 0:
        print("获取拓扑失败!")
        sys.exit(1)

    # 通过appId清空这个App之前下发的所有流表项​
    appId = "org.onosproject.core"
    status_code, resp = del_flows_by_appId(ip, appId)
    print(status_code)

    # # 在所有交换机下发Drop流表项屏蔽fwd转发功能​
    appId = "disable.fwd"
    for deviceId in devices_id:
        status_code, resp = disable_fwd(ip, appId, deviceId)

    # 链路规划
    graph = dict()
    
    for link in links:
        if graph.get(link['src']['device']) is not None:
            graph[link['src']['device']][link['dst']['device']] = 1
        else:
            graph[link['src']['device']] = dict()
            graph[link['src']['device']][link['dst']['device']] = 1


    appId = "myflow"
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
                        status_code = add_flows('127.0.0.1', path[k], appId, hosts[i]["mac"], hosts[j]["mac"], sw_port_src, sw_port_dst)
                        print(status_code)
                        status_code = add_flows('127.0.0.1', path[k], appId, hosts[j]["mac"], hosts[i]["mac"], sw_port_dst, sw_port_src)
                        print(status_code)
                        sw_port_src = link["dst"]["port"]
                        break
            
            sw_port_dst = hosts[j]["locations"][0]["port"]
            status_code = add_flows('127.0.0.1', path[-1], appId, hosts[i]["mac"], hosts[j]["mac"], sw_port_src, sw_port_dst)
            print(status_code)
            status_code = add_flows('127.0.0.1', path[-1], appId, hosts[j]["mac"], hosts[i]["mac"], sw_port_dst, sw_port_src)
            print(status_code)