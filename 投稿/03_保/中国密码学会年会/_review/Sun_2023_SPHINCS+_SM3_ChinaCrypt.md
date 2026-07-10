# SPHINCS+-SM3: 基于SM3的无状态数字签名算法

**出处**: 中国密码学会年会 (ChinaCrypt 2023), 后发表于《密码学报》2023, Vol.10(6)
**作者**: 孙思维, 刘田雨, 关志, 何逸飞, 胡磊, 荆继武, 张立廷, 闫海伦

## 论点
使用中国国密哈希SM3全量替换SPHINCS+的SHA-256/SHAKE-256，提供NIST PQC Level-1安全性的参数集。

## 背景
NIST将SPHINCS+标准化为FIPS 205，但其官方实例仅支持SHA-2/SHAKE。中国密码应用需要符合国密标准的后量子签名。SM3（GB/T 32905-2016）是自然选择。

## 技术路线
- 全量替换PRF/PRF_msg/H_msg/thash为SM3+域分离
- WOTS+/FORS/Hypertree结构不变
- 域分离：不同前缀区分THF调用类型

## 核心成果
- 两组Level-1参数集
- 性能与SHA-256版SPHINCS+相当
- ChinaCrypt宣讲+密码学报发表

## 与本项目关联
**方法论参考**: 与本项目共享"替换SPHINCS+底层哈希"方法论。SM3是传统哈希→传统哈希，本项目是传统哈希→ZK友好哈希(Poseidon2)。
