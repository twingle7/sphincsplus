# A Survey on Exotic Signatures for Post-quantum Blockchain: Challenges and Research Directions

**出处**: ACM Computing Surveys, Vol. 55, No. 12, Article 251, 2023
**作者**: Maxime Buser, Rafael Dowsley, Muhammed F. Esgin, Clementine Gritti, Shabnam Kasra Kermanshahi, Veronika Kuchta, Jason T. LeGrow, Joseph K. Liu, Raphael C.-W. Phan, Amin Sakzad, Ron Steinfeld, Jiangshan Yu

## 论点
后量子区块链生态中，具备高级特性的"奇异签名"（盲签名、环签名、阈值签名、聚合签名、适配器签名）是实现隐私保护、共识优化和无脚本区块链的关键基础设施，但目前在效率、安全模型和标准化方面仍存在重大挑战。

## 背景
区块链的广泛应用越来越依赖各类高级签名协议来支撑账户管理、隐私增强和共识效率。然而现有大多数方案基于经典安全假设（ECDSA、BLS），量子计算威胁尚未被充分应对。该综述立足于后量子密码转型的早期阶段，系统梳理了格、哈希、编码、多变量和同源五大后量子假设下的奇异签构造。

## 技术路线
以"应用目的"为分类轴心（账户管理/共识效率/无脚本区块链/隐私保护），逐一审查每个类别中各后量子假设下现有构造的安全性、效率和标准化状态。采用统一的对比表格呈现签名/验证时间、签名体积和安全级别等基准数据，并针对每个后量子假设族讨论其技术特点与开放问题。

## 核心成果
1. 构建了首个系统的后量子奇异签名全景图谱，覆盖五种后量子假设和五类奇异签名功能。
2. 识别出格基方案在功能完备性方面领先但效率瓶颈突出，哈希基方案在简单性方面具有优势。
3. 明确指出盲签名和环签名是区块链隐私保护的核心工具，但后量子实例大多仅停留在理论阶段。

## 与本项目关联
**背景知识**: 为本项目中盲签名+STARK证明的技术路线提供了全景坐标参考，确认了哈希基方案的竞争力。
