# Clustering of unknown protocol messages based on format comparison 论文实验部分复现

原文地址：https://www.sciencedirect.com/science/article/pii/S138912862030445X?via%3Dihub

论文精读：https://solar1s.t0nkov.site/posts/clustering_of_unknown_protocol_messages_based_on_format_comparison/

Abstract:

作为一种检测和分析未知或专有协议的解决方案，协议逆向工程（PRE）近年来得到了迅速发展。在这个领域，针对协议格式的消息聚类是区分未知协议消息的基本解决方案。
本文研究未知协议的面向格式的消息聚类问题，包括来自专有或非合作网络环境的未知规范的消息。通过引入ABNF的基本规则，我们定义了Token Format Distance (TFD) 和 Message Format Distance (MFD) 以表示token和消息的格式相似性，并引入Jaccard Distance和优化的序列对齐算法（MFD度量）来计算它们。然后，我们使用MFD构建一个距离矩阵，并将其输入DBSCAN算法，将未知协议消息聚类为具有不同格式的类。在这个过程中，我们设计了一个无监督聚类策略，将轮廓系数和Dunn指数应用于DBSCAN的参数选择。
在对两个数据集的实验中，结果聚类的同质性和完整性的调和平均v-measures均在0.91以上，fmis和覆盖率s均不低于0.97。同时，通过箱线图分析，v-measure和fmi的iqr分别低于0.1和0.03，证明了该方法具有显著的有效性和稳定性。对这些指标的综合分析和比较还表明，我们的方法比以前的工作具有相当的优势。