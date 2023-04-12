# Clustering of unknown protocol messages based on format comparison 论文实验部分复现

原文地址：https://www.sciencedirect.com/science/article/pii/S138912862030445X?via%3Dihub

论文精读：https://solar1s.t0nkov.site/posts/clustering_of_unknown_protocol_messages_based_on_format_comparison/

<<<<<<< HEAD
Abstract:

作为一种检测和分析未知或专有协议的解决方案，协议逆向工程（PRE）近年来得到了迅速发展。在这个领域，针对协议格式的消息聚类是区分未知协议消息的基本解决方案。
本文研究未知协议的面向格式的消息聚类问题，包括来自专有或非合作网络环境的未知规范的消息。通过引入ABNF的基本规则，我们定义了Token Format Distance (TFD) 和 Message Format Distance (MFD) 以表示token和消息的格式相似性，并引入Jaccard Distance和优化的序列对齐算法（MFD度量）来计算它们。然后，我们使用MFD构建一个距离矩阵，并将其输入DBSCAN算法，将未知协议消息聚类为具有不同格式的类。在这个过程中，我们设计了一个无监督聚类策略，将轮廓系数和Dunn指数应用于DBSCAN的参数选择。
在对两个数据集的实验中，结果聚类的同质性和完整性的调和平均v-measures均在0.91以上，fmis和覆盖率s均不低于0.97。同时，通过箱线图分析，v-measure和fmi的iqr分别低于0.1和0.03，证明了该方法具有显著的有效性和稳定性。对这些指标的综合分析和比较还表明，我们的方法比以前的工作具有相当的优势。
=======
### Abstract
As a solution to detect and analyse unknown or proprietary protocols, Protocol Reverse Engineering(PRE) has been developed swiftly in recent years. In this field, message clustering aimed at protocol format serves as a fundamental solution for differentiating of unknown protocol messages. This paper works on the problem of format-oriented message clustering of unknown protocols, including messages from proprietary or non-cooperative network environments with their specifications unknown. By introducing basic rules of ABNF, we define Token Format Distance (TFD) and Message Format Distance (MFD) to represent format similarity of tokens and messages, and introduce Jaccard Distance and an optimized sequence alignment algorithm (MFD measurement) to compute them. Then, a distance matrix is built by MFD and we feed it to DBSCAN algorithm to cluster unknown protocol messages into classes with different formats. In this process, we design an unsupervised clustering strategy with Silhouette Coefficient and Dunn Index applied to parameter selecting of DBSCAN. In experiment on two datasets, the harmonic average v-measures of homogeneity and completeness on result clusters are both above 0.91, with fmis and coverages no less than 0.97. Together with iqr of v-measure and fmi bellow 0.1 and 0.03 separately in boxplot analyses, this method is proved to have remarkable validity and stability. Comprehensive analyses and comparisons on these indexes also show considerable advantages of our method over previous work.
>>>>>>> 30da74d99ee64c658747cb4e3966fc4777dbe1b8
