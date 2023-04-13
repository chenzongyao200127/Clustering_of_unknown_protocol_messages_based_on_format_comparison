# 消息字节生成属性集
# ---------------
# 
# from scapy.all import *

# # 假设 `packet` 是您捕获或读取的数据包对象
# packet = ...  # 用实际的数据包替换此占位符

# # 提取应用层负载（通常为 TCP 或 UDP 层）
# payload = packet[TCP].payload if TCP in packet else packet[UDP].payload

# # 将负载转换为字节串并获取前 20 字节
# header_bytes = bytes(payload)[:20]

# 根据需求，可能需要使用 scapy 中的 sniff() 函数捕获实时网络流量，或者使用 rdpcap() 函数读取保存在文件中的数据包。

def get_attributes(byte):
    attributes = set()
    
    if byte == 0x0D:
        attributes.add("CR")
    if byte == 0x0A:
        attributes.add("LF")
    if byte == 0x09:
        attributes.add("HTAB")
    if byte == 0x20:
        attributes.add("SP")
    if byte == 0x22:
        attributes.add("DQUOTE")
    if 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A:
        attributes.add("ALPHA")
    if 0x01 <= byte <= 0x7F:
        attributes.add("CHAR")
    if 0x00 <= byte <= 0x1F:
        attributes.add("CTL")
    if 0x30 <= byte <= 0x39:
        attributes.add("DIGIT")
    if 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x46:
        attributes.add("HEXDIG")
    if 0x00 <= byte <= 0xFF:
        attributes.add("OCTET")
    if 0x21 <= byte <= 0x7E:
        attributes.add("VCHAR")
    
    return attributes

def generate_attribute_sets(message):
    attribute_sets = []
    for byte in message:
        attributes = get_attributes(byte)
        attribute_sets.append(attributes)
    return attribute_sets


def token_format_distance(set1, set2):
    return 1 - len(set1.intersection(set2)) / len(set1.union(set2))

def calculate_tfd_matrix(message1_attribute_sets, message2_attribute_sets):
    tfd_matrix = [[0 for _ in range(len(message2_attribute_sets))] for _ in range(len(message1_attribute_sets))]
    
    for i, set1 in enumerate(message1_attribute_sets):
        for j, set2 in enumerate(message2_attribute_sets):
            tfd_matrix[i][j] = token_format_distance(set1, set2)
    
    return tfd_matrix

def print_matrix(tfd_matrix):
    print("Token Format Distance Matrix:")
    for row in tfd_matrix:
        # print([round(x, 2) for x in row])
        print(', '.join([f"{x:.2f}" for x in row]))
        
def token_based_distance(seq1, seq2):
    n = len(seq1)
    m = len(seq2)

    # 初始化距离矩阵
    d = [[0 for _ in range(m+1)] for _ in range(n+1)]

    # 填充第一行和第一列
    for i in range(n+1):
        d[i][0] = i
    for j in range(m+1):
        d[0][j] = j

    seq1_attribute_sets = generate_attribute_sets(seq1)
    seq2_attribute_sets = generate_attribute_sets(seq2)
    tfd_matrix = calculate_tfd_matrix(seq1_attribute_sets, seq2_attribute_sets)

    # 动态规划填充矩阵
    for i in range(1, n+1):
        for j in range(1, m+1):
            # 计算标记距离
            token_distance = tfd_matrix[i-1][j-1]

            # 更新距离矩阵
            d[i][j] = min(d[i-1][j] + 1, d[i][j-1] + 1, d[i-1][j-1] + token_distance)

    # 返回序列之间的距离
    return d[n][m]

def main():
    # 论文中的例子
    
    message1 = [0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a]
    message2 = [0x50, 0x4F, 0x53, 0x54, 0x20, 0x2F, 0x61, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a]
    
    print("message1:" + ''.join([f"{chr(x)}" for x in message1]))
    print("message2:" + ''.join([f"{chr(x)}" for x in message2]))

    message1_attribute_sets = generate_attribute_sets(message1)
    message2_attribute_sets = generate_attribute_sets(message2)

    tfd_matrix = calculate_tfd_matrix(message1_attribute_sets, message2_attribute_sets)
    print_matrix(tfd_matrix)
    
    distance = token_based_distance(message1, message2)
    print("MFD between message1 and message2:", distance)
    

if __name__ == '__main__':
    main()