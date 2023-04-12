import dpkt
import os
import shutil
import socket

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

if __name__ == '__main__':
    data_path = 'data_lol'
    file_name_list = os.listdir(data_path)
    
    count = 0
    tcp_flow_dict = dict()
    udp_flow_dict = dict()
    for file_name in file_name_list:
        try:
            f = open(os.path.join(data_path, file_name), 'rb')
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6): # 解包，网络层，判断网络层是否存在，兼容ipv6
                    continue
                ip = eth.data
                # ip = dpkt.ip.IP(buf[12:])
                if ip.v == 4:
                    if ip.p == dpkt.ip.IP_PROTO_TCP: # TCP
                        tcp = ip.data
                        data = tcp.data




                        # new_flow = flow('tcp', socket.inet_ntop(socket.AF_INET,ip.src), socket.inet_ntop(socket.AF_INET, ip.dst), str(tcp.sport), str(tcp.dport))
                        # if new_flow not in tcp_flow_dict:
                        #     tcp_flow_dict[new_flow] = [(ts, buf)]
                        # else:
                        #     tcp_flow_dict[new_flow].append((ts,buf))
                    elif ip.p == dpkt.ip.IP_PROTO_UDP: # UDP
                        udp = ip.data
                        if (udp.sport == 53) or (udp.dport == 53): # UDP，过滤53端口的DNS报文
                            continue
                        # new_flow = flow('udp', socket.inet_ntop(socket.AF_INET,ip.src), socket.inet_ntop(socket.AF_INET, ip.dst), str(udp.sport), str(udp.dport))
                        # if new_flow not in udp_flow_dict:
                        #     udp_flow_dict[new_flow] = [(ts, buf)]
                        # else:
                        #     udp_flow_dict[new_flow].append((ts, buf))
                else:
                    continue
        except Exception as e:
            print("[error] {0}".format(e))
    
    print(len(tcp_flow_dict))
    print(len(udp_flow_dict))
    print("-" * 40)
    for key, value in tcp_flow_dict.items():
        print('TCP Flow: ', end='')
        try:
            print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
                                                                                       key.dst_ip,
                                                                                       key.src_port, key.dst_port,
                                                                                       len(value)))
        except:
            print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
                                                                                       key.dst_ip,
                                                                                       key.src_port, key.dst_port, len(value)))

    for key, value in udp_flow_dict.items():
        print('UDP Flow: ', end='')
        try:
            print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
                                                                                       key.dst_ip,
                                                                                       key.src_port, key.dst_port,
                                                                                       len(value)))
        except:
            print("ip.src:{0}, ip.dst:{1}, src_port:{2}, dst_port:{3} data:{4}".format(key.src_ip,
                                                                                       key.dst_ip,
                                                                                       key.src_port, key.dst_port, len(value)))
    print(len(tcp_flow_dict)+len(udp_flow_dict))
    
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
