# SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost

**出处**: IEEE S&P 2023, pp. 1435-1453
**作者**: Andreas Hülsing, Mikhail A. Kudinov, Eyal Ronen, Eylon Yogev

## 论点
提出SPHINCS+C——通过对WOTS+和FORS的优化组合，在几乎不牺牲安全性或性能的前提下，将SPHINCS+签名大小压缩约20%。

## 背景
SPHINCS+的签名大小（7.8-49.8KB）是其主要缺点。压缩签名大小对于带宽受限场景（如区块链、证书传输）至关重要。但任何优化不能破坏SPHINCS+的紧致安全归约。

## 技术路线
- WOTS+C：压缩Winternitz链的编码方式，减少链长度
- FORS+C：优化FORS树的叶节点编码
- 保持THF安全性质不变
- 安全归约保持紧致

## 核心成果
- 签名大小减少约20%（128-bit从7856→6304字节）
- 签名/验证时间几乎不变
- 安全性无损

## 与本项目关联
**方法论参考**: SPHINCS+C的优化思路（在不改变安全模型的条件下压缩签名）可应用于本项目的参数优化。Poseidon2版本的WOTS+/FORS是否也存在类似的压缩空间是值得探索的方向。
