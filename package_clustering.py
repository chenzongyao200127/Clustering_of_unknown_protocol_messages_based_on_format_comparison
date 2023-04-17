import dpkt
import os
import shutil
import socket
from pprint import pprint
import random
from typing import Dict, List
from Message_Format_Distance_measurement import *
import numpy as np


def get_last_directory(file_path):
    # 获取文件路径的目录部分
    directory_path = os.path.dirname(file_path)
    # 获取目录路径的最后一个部分
    last_directory = os.path.basename(directory_path)
    return last_directory

def create_label_dict(protocols: List) -> dict:
    protocol_to_label_map = dict()
    idx = 0
    for protocol in protocols:
        if protocol not in protocol_to_label_map.keys():
            protocol_to_label_map[protocol] = idx
            idx += 1
            
    return protocol_to_label_map
    
        
def select_random_packets(protocols: Dict, num_packets: int = 1024, head_lngth: int = 20) -> dict:
    # 计算所有数据包的总数
    total_packets = sum(len(packets) for packets in protocols.values())

    # 确保可以从数据集中至少选择指定数量的数据包
    if total_packets < num_packets:
        raise ValueError("There are not enough packets in the input dictionary.")

    # 从所有数据包中随机选择指定数量的数据包
    all_packets = [packet for packets in protocols.values() for packet in packets]
    selected_packets = random.choices(all_packets, k=num_packets)

    # 将选择的数据包组成新的字典
    new_dict = dict()
    for packet in selected_packets:
        for protocol, packets in protocols.items():
            if packet in packets:
                if protocol not in new_dict:
                    new_dict[protocol] = []
                # pprint(''.join([f"{chr(x)}" for x in bytes(packet)[:head_lngth]]))
                new_dict[protocol].append(get_first_n_bytes(bytes(packet), head_lngth))
                break
    
    # pprint(sum(len(packets) for packets in new_dict.values()))
    
    return new_dict

# 获取数据包前n个字节的功能
def get_first_n_bytes(packet_data, n):
    try:
        if n > len(packet_data):
            # raise ValueError("n is greater than the length of the packet data")
            first_n_bytes = packet_data

        # 获取前n个字节
        first_n_bytes = packet_data[:n]
        return first_n_bytes
    except Exception as e:
        print(f"Error: {e}")
        return None


def walk_files(data_path):
    file_name_list = []
    for dirpath, dirnames, filenames in os.walk(data_path):
        # print("当前目录路径:", dirpath)
        # print("文件列表:", filenames)
        # print("-" * 40)
        for file in filenames:
            file_name_list.append(os.path.join(dirpath, file))
    return file_name_list



def process_pcap_file(file_name, packge_dict):
    try:
        last_directory = get_last_directory(file_name)
        with open(file_name, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
                    continue

                ip = eth.data

                if ip.v == 4:
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        tcp = ip.data
                        packge_dict[str(last_directory)].append(tcp.data)
                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        udp = ip.data

                        if (udp.sport == 53) or (udp.dport == 53):
                            continue
                        packge_dict[str(last_directory)].append(udp.data)
                else:
                    continue
    except Exception as e:
        print("[error] {0}".format(e))


def print_package_count(packge_dict):
    total = 0
    for k, v in packge_dict.items():
        print(k + ": " + str(len(v)))
        total += len(v)
    print("total package: ", total)
    # print(str(total / 1024))
    

def main():
    data_path = 'data_tmp'
    packge_dict = dict()
    file_name_list = walk_files(data_path)

    '''
    修改参数取样数量 和 数据包slice长度
    '''    
    head_length = 20
    sample_nums = 1024

    for file_name in file_name_list:
        last_directory = get_last_directory(file_name)
        packge_dict[str(last_directory)] = []

    for file_name in file_name_list:
        process_pcap_file(file_name, packge_dict)

    print("-" * 40)
    print_package_count(packge_dict)
    new_dict = select_random_packets(packge_dict, sample_nums, head_length)
    pprint(sum(len(packets) for packets in new_dict.values()))
    
    # message1 = [0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a]
    # message2 = [0x50, 0x4F, 0x53, 0x54, 0x20, 0x2F, 0x61, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a]
    
    # print("message1:" + ''.join([f"{chr(x)}" for x in message1]))
    # print("message2:" + ''.join([f"{chr(x)}" for x in message2]))
    
    label_collect = []
    packet_collect = []
    
    
    
    for k,v in new_dict.items():
        for packet_slice in v:
            label_collect.append(k)   
            packet_collect.append(packet_slice)
        
    # pprint(label_collect)
    # pprint(packet_collect)
    
    # MFD_matrix = [[0 for _ in range(sample_nums)] for _ in range(sample_nums)]
    MFD_matrix = np.zeros((sample_nums, sample_nums), dtype=np.float16)

    
    for i in range(sample_nums):
        for j in range(sample_nums):
            # message1_attribute_sets = generate_attribute_sets(packet_collect[i])
            # message2_attribute_sets = generate_attribute_sets(packet_collect[j])
            
            # tfd_matrix = calculate_tfd_matrix(message1_attribute_sets, message2_attribute_sets)
            # print_matrix(tfd_matrix)
            
            distance = token_based_distance(packet_collect[i], packet_collect[j])
            MFD_matrix[i][j] = distance
            
    # print_matrix(MFD_matrix)
    
    # 数据标准化
    # from sklearn.preprocessing import StandardScaler
    
    # MFD_matrix = StandardScaler().fit_transform(MFD_matrix)
    
    # 绘制散点图
    import matplotlib.pyplot as plt
    
    plt.scatter(MFD_matrix[:, 0], MFD_matrix[:, 1])
    plt.savefig("sample.png")
    
    
    protocol_to_label_map = create_label_dict(label_collect)
    print("protocol to label:", protocol_to_label_map)
    
    # labels_true 是一个包含每个样本所属簇的真实标签的一维数组。
    labels_true = np.zeros(len(label_collect), dtype=np.int_)
    for i in range(len(label_collect)):
        labels_true[i] = protocol_to_label_map[label_collect[i]]
        
    
    from sklearn.cluster import DBSCAN
    from sklearn import metrics


    '''
    DBSCAN 聚类 调整参数
    '''
    db = DBSCAN(eps=0.3, min_samples=10).fit(MFD_matrix)
    
    # db.labels_ 属性包含每个样本的聚类标签。噪声点将被赋予标签 -1
    labels = db.labels_
    
    pprint(labels_true)
    pprint(labels)
    

    # Number of clusters in labels, ignoring noise if present.
    # n_clusters_ 计算去除噪声点后的簇的数量
    # n_noise_ 计算标签中噪声点的数量
    n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise_ = list(labels).count(-1)

    print("Estimated number of clusters: %d" % n_clusters_)
    print("Estimated number of noise points: %d" % n_noise_)
    
    # 同质性（hom.）、完整性（com.）、V-度量（v.）、FMI和覆盖率（cov.）
    print(f"Homogeneity(同质性): {metrics.homogeneity_score(labels_true, labels):.3f}")
    print(f"Completeness(完整性): {metrics.completeness_score(labels_true, labels):.3f}")
    print(f"V-measure(V-度量): {metrics.v_measure_score(labels_true, labels):.3f}")
    print(f"Adjusted Rand Index: {metrics.adjusted_rand_score(labels_true, labels):.3f}")
    print(
        "Adjusted Mutual Information:"
        f" {metrics.adjusted_mutual_info_score(labels_true, labels):.3f}"
    )
    print(f"Silhouette Coefficient: {metrics.silhouette_score(MFD_matrix, labels):.3f}")
    
    
    
    unique_labels = set(labels)
    core_samples_mask = np.zeros_like(labels, dtype=bool)
    core_samples_mask[db.core_sample_indices_] = True

    colors = [plt.cm.Spectral(each) for each in np.linspace(0, 1, len(unique_labels))]
    for k, col in zip(unique_labels, colors):
        if k == -1:
            # Black used for noise.
            col = [0, 0, 0, 1]

        class_member_mask = labels == k

        xy = MFD_matrix[class_member_mask & core_samples_mask]
        plt.plot(
            xy[:, 0],
            xy[:, 1],
            "o",
            markerfacecolor=tuple(col),
            markeredgecolor="k",
            markersize=13,
        )

        xy = MFD_matrix[class_member_mask & ~core_samples_mask]
        plt.plot(
            xy[:, 0],
            xy[:, 1],
            "o",
            markerfacecolor=tuple(col),
            markeredgecolor="k",
            markersize=5,
        )

    # plt.title(f"Estimated number of clusters: {n_clusters_}")
    # plt.show()
    plt.title(f"Estimated number of clusters: {n_clusters_}")
    plt.savefig("cluster_sample.png")  # 保存图片到文件


    from scipy.spatial.distance import pdist
    from scipy.cluster.hierarchy import linkage, fcluster
    from sklearn_extra.cluster import KMedoids
    from sklearn import metrics

    # 计算距离矩阵
    distance_matrix = pdist(MFD_matrix)

    # UPGMA 聚类
    Z = linkage(distance_matrix, method='average')
    num_clusters = len(protocol_to_label_map)  #更改聚类数量
    labels_upgma = fcluster(Z, num_clusters, criterion='maxclust') - 1  # 减1以使标签从0开始

    # PAM 聚类
    kmedoids = KMedoids(n_clusters=num_clusters, init='k-medoids++', random_state=42)
    labels_pam = kmedoids.fit_predict(MFD_matrix)
    
    # 评价指标 - 同质性、完整性、V-度量、FMI 和覆盖率
    hom_upgma, com_upgma, v_upgma = metrics.homogeneity_completeness_v_measure(labels_true, labels_upgma)
    fmi_upgma = metrics.fowlkes_mallows_score(labels_true, labels_upgma)
    cov_upgma = np.mean(labels_upgma == labels_true)

    hom_pam, com_pam, v_pam = metrics.homogeneity_completeness_v_measure(labels_true, labels_pam)
    fmi_pam = metrics.fowlkes_mallows_score(labels_true, labels_pam)
    cov_pam = np.mean(labels_pam == labels_true)

    print("UPGMA 聚类结果：")
    print("同质性（homogeneity）：", hom_upgma)
    print("完整性（completeness）：", com_upgma)
    print("V-度量（v-measure）：", v_upgma)
    print("FMI（Fowlkes-Mallows score）：", fmi_upgma)
    print("覆盖率（coverage）：", cov_upgma)

    print("\nPAM 聚类结果：")
    print("同质性（homogeneity）：", hom_pam)
    print("完整性（completeness）：", com_pam)
    print("V-度量（v-measure）：", v_pam)
    print("FMI（Fowlkes-Mallows score）：", fmi_pam)
    print("覆盖率（coverage）：", cov_pam)
    

    # # 评价指标 - 调整兰德指数（ARI）和调整互信息（AMI）
    # ari_upgma = metrics.adjusted_rand_score(labels_true, labels_upgma)
    # ami_upgma = metrics.adjusted_mutual_info_score(labels_true, labels_upgma)

    # ari_pam = metrics.adjusted_rand_score(labels_true, labels_pam)
    # ami_pam = metrics.adjusted_mutual_info_score(labels_true, labels_pam)

    # print("UPGMA 聚类结果：")
    # print("调整兰德指数（ARI）：", ari_upgma)
    # print("调整互信息（AMI）：", ami_upgma)

    # print("\nPAM 聚类结果：")
    # print("调整兰德指数（ARI）：", ari_pam)
    # print("调整互信息（AMI）：", ami_pam)
    
    
    
    # # 获取矩阵的行数和列数
    # rows, cols = MFD_matrix.shape

    # # 生成 X 和 Y 坐标数组
    # x_coords = np.repeat(np.arange(rows), cols)
    # y_coords = np.tile(np.arange(cols), rows)

    # # 绘制散点图
    # plt.scatter(x_coords, y_coords, c=MFD_matrix.flatten(), cmap='viridis')
    # plt.colorbar(label='Value')  # 添加颜色条
    # plt.xlabel('X Coordinate')
    # plt.ylabel('Y Coordinate')
    # plt.title('Scatter plot of a matrix')
    # plt.savefig("sample.png") 
    
    

    # message1_attribute_sets = generate_attribute_sets(message1)
    # message2_attribute_sets = generate_attribute_sets(message2)

    # tfd_matrix = calculate_tfd_matrix(message1_attribute_sets, message2_attribute_sets)
    # print_tfd_matrix(tfd_matrix)
    
    # distance = token_based_distance(message1, message2)
    # print("MFD between message1 and message2:", distance)


if __name__ == '__main__':
    main()
    
    
    # data_path = 'data_tmp'
    
    # # tcp_packge_dict = dict()
    # # udp_packge_dict = dict()
    
    # packge_dict = dict()
    
    # # 获取目录中所有文件的文件名列表
    # file_name_list = []
    # for dirpath, dirnames, filenames in os.walk(data_path):
    #     print("当前目录路径:", dirpath)
    #     print("文件列表:", filenames)
    #     print("-" * 40)
    #     for file in filenames:
    #         file_name_list.append(os.path.join(dirpath, file))
            
    
    # count = 0
    
    # # 存储 TCP 和 UDP 流
    # # tcp_flow_dict = dict()
    # # udp_flow_dict = dict()
    
    # for file_name in file_name_list:
    #     last_directory = get_last_directory(file_name)
    #     packge_dict[str(last_directory)] = []
    
    
    # for file_name in file_name_list:
    #     try:
    #         print(file_name)
    #         last_directory = get_last_directory(file_name)
            
    #         f = open(file_name, 'rb')
    #         # 使用 dpkt 库创建 pcap 文件阅读器
    #         pcap = dpkt.pcap.Reader(f)

    #         # 遍历 pcap 文件中的每个数据包及其时间戳
    #         for ts, buf in pcap:
    #             # 解析数据包为以太网帧
    #             eth = dpkt.ethernet.Ethernet(buf)
                
    #             # 检查网络层是否是 IPv4 或 IPv6
    #             if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6): # 解包，网络层，判断网络层是否存在，兼容ipv6
    #                 continue
                
    #             # 获取 IP 层数据
    #             ip = eth.data
                
    #             # ip = dpkt.ip.IP(buf[12:])
    #             if ip.v == 4:
    #                 # 检查是否为 TCP 数据包
    #                 if ip.p == dpkt.ip.IP_PROTO_TCP: # TCP
                        
    #                     tcp = ip.data
    #                     # data = tcp.data
                        
    #                     packge_dict[str(last_directory)].append(tcp)

    #                     # new_flow = flow('tcp', socket.inet_ntop(socket.AF_INET,ip.src), socket.inet_ntop(socket.AF_INET, ip.dst), str(tcp.sport), str(tcp.dport))
    #                     # if new_flow not in tcp_flow_dict:
    #                     #     tcp_flow_dict[new_flow] = [(ts, buf)]
    #                     # else:
    #                     #     tcp_flow_dict[new_flow].append((ts,buf))
                        
    #                 elif ip.p == dpkt.ip.IP_PROTO_UDP: # UDP
                        
    #                     udp = ip.data
                        
    #                     if (udp.sport == 53) or (udp.dport == 53): # UDP，过滤53端口的DNS报文
    #                         continue
                        
    #                     packge_dict[str(last_directory)].append(udp)
                        
    #                     # new_flow = flow('udp', socket.inet_ntop(socket.AF_INET,ip.src), socket.inet_ntop(socket.AF_INET, ip.dst), str(udp.sport), str(udp.dport))
    #                     # if new_flow not in udp_flow_dict:
    #                     #     udp_flow_dict[new_flow] = [(ts, buf)]
    #                     # else:
    #                     #     udp_flow_dict[new_flow].append((ts, buf))
    #             else:
    #                 continue
    #     except Exception as e:
    #         print("[error] {0}".format(e))
    
    # print("-" * 40)
    
    # total = 0
    # for k,v in packge_dict.items():
    #     print(k + ": " + str(len(v)))
    #     total += len(v)
        
    # print("total package: ", total)
    # print(str(total / 1024))
    
    # new_dict = select_random_packets(packge_dict, 1024)
    # pprint(sum(len(packets) for packets in new_dict.values()))
    
    
# class flow:
#     def __init__(self, trans_pro, src_ip, dst_ip, src_port, dst_port):
#         self.trans_pro = trans_pro
#         self.src_ip = src_ip
#         self.dst_ip = dst_ip
#         self.src_port = src_port
#         self.dst_port = dst_port

#     def __eq__(self, other):
#         flag_1 = self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and self.src_port == other.src_port and self.dst_port == other.dst_port
#         flag_2 = self.src_ip == other.dst_ip and self.dst_ip == other.src_ip and self.src_port == other.dst_port and self.dst_port == other.src_port
#         return flag_1 or flag_2

#     def __hash__(self):
#         string_flow = str(sorted([self.src_ip, self.dst_ip]) + sorted([self.src_port, self.dst_port]))
#         return hash(string_flow)
    
    
    # for tcp in tcp_packge_list:
    #     pprint(tcp)
        # print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(tcp.src_ip,
        #                                                                            tcp.dst_ip,
        #                                                                            tcp.src_port, 
        #                                                                            tcp.dst_port,
        #                                                                            tcp.data))
    
    # for udp in udp_packge_list:
    #     pprint(udp)
    
    
    # for key, value in tcp_flow_dict.items():
    #     print('TCP Flow: ', end='')
    #     try:
    #         print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
    #                                                                                    key.dst_ip,
    #                                                                                    key.src_port, key.dst_port,
    #                                                                                    len(value)))
    #     except:
    #         print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
    #                                                                                    key.dst_ip,
    #                                                                                    key.src_port, key.dst_port, len(value)))

    # for key, value in udp_flow_dict.items():
    #     print('UDP Flow: ', end='')
    #     try:
    #         print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
    #                                                                                    key.dst_ip,
    #                                                                                    key.src_port, key.dst_port,
    #                                                                                    len(value)))
    #     except:
    #         print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
    #                                                                                    key.dst_ip,
    #                                                                                    key.src_port, key.dst_port, len(value)))
    # print(len(tcp_flow_dict)+len(udp_flow_dict))
    
    # print('[In] Result path: ', end='')
    # result_path = input()
    # # print(result_path)
    # if not os.path.exists(result_path):
    #     os.mkdir(result_path)
    # else:
    #     shutil.rmtree(result_path)  # 删除
    #     os.mkdir(result_path) # 再建立

    # # 写入tcp流量
    # for i, value in zip(range(len(tcp_flow_dict.values())), tcp_flow_dict.values()):
    #     if len(value) <5:
    #         continue
    #     file_path = os.path.join(result_path, result_path +  '_' + str(i) + "_tcp.pcap")
    #     flow_new = open(file_path, 'wb')
    #     writer = dpkt.pcap.Writer(flow_new)
    #     value.sort(key = lambda x:x[0], reverse=False)
    #     for pkt in value:
    #         writer.writepkt(pkt = pkt[1], ts = pkt[0])
    #     flow_new.close()

    # #写入udp流量
    # for i, value in zip(range(len(udp_flow_dict.values())), udp_flow_dict.values()):
    #     if len(value) <5:
    #         continue
    #     file_path = os.path.join(result_path, result_path +  '_' + str(i) + "_udp.pcap")
    #     flow_new = open(file_path, 'wb')
    #     writer = dpkt.pcap.Writer(flow_new)
    #     value.sort(key = lambda x:x[0], reverse=False)
    #     for pkt in value:
    #         writer.writepkt(pkt = pkt[1], ts = pkt[0])
    #     flow_new.close()

    # file_name_list = os.listdir(result_path)
    # for file_name in file_name_list:
    #     # print(file_name)
    #     if 'tcp' in file_name: # TCP去重传、乱序
    #         write_biflow_to_file(os.path.join(result_path, file_name))

    # print('[Out] Result restore in the file floder: ' + result_path)
