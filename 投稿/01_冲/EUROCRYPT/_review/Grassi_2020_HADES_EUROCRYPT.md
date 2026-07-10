# On a Generalization of Substitution-Permutation Networks: The HADES Design Strategy

**出处**: EUROCRYPT 2020
**作者**: Lorenzo Grassi, Reinhard Luftenegger, Christian Rechberger, Dragos Rotaru, Markus Schofnegger

## 论点
提出HADES（Half-And-round-with-Different- Equations）——一种新的SPN设计策略：外部轮次使用完整S-box层提供密码学强度，内部轮次仅用一个S-box减少电路约束。这是Poseidon/Poseidon2的底层设计理论。

## 背景
传统SPN每轮使用相同结构（如同AES），但ZK证明场景中非线性操作（S-box）成本远高于线性操作。需要一种非对称结构在安全性与效率间取得平衡。

## 技术路线
- 外部轮次（RF）：全部t个S-box活跃+MDS矩阵
- 内部轮次（RP）：仅1个S-box活跃+稀疏线性层
- 约束数量与RP·1而非RF·t成正比
- 安全性分析：Gröbner基攻击、差分/线性密码分析
- 参数选择公式：RF和RP的最小安全取值

## 核心成果
- HADES成为ZK友好哈希的设计范式
- 直接催生了Poseidon（USENIX 2021）和Poseidon2（AFRICACRYPT 2023）
- 在R1CS中比AES-like SPN快数十倍

## 与本项目关联
**背景知识/方法论参考**: Poseidon2的HADES设计直接决定了本项目STARK电路中哈希约束的效率。理解内部轮次（仅1个S-box）的稀疏约束是理解全内生AIR仅需16个约束的关键。
