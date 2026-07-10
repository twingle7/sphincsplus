# SPHINCS+ Post-quantum Digital Signature Scheme with Streebog Hash Function

**出处**: AIP Conference Proceedings, Vol. 2241, 020014, 2020
**作者**: E. O. Kiktenko, A. A. Bulychev, P. A. Karagodin, N. O. Pozhar, M. N. Anufriev, A. K. Fedorov

## 论点
将俄罗斯国家标准哈希函数Streebog（GOST R 34.11-2012）替换为SPHINCS+的底层哈希原语，可以在兼容俄标密码体系的前提下实现后量子数字签名，且性能与SHA-256实例化相当。

## 背景
俄罗斯联邦对密码标准化有独立要求，GOST系列算法（包括Streebog哈希和Kuznyechik分组密码）是官方强制标准。在后量子签名领域，SPHINCS+是NIST选定方案之一，但初始版本仅支持SHA-256/SHAKE。作者评估了将SPHINCS+纳入俄罗斯标准化体系的可行性和性能代价。

## 技术路线
保留SPHINCS+完整框架（WOTS+/FORS/hypertree）不变，将Streebog作为256比特输出哈希函数替换SHA-256。对不同安全级别参数集（128/192/256比特）分别实现并基准测试。Streebog基于Streebog-Kuznyechik压缩函数（类似Miyaguchi-Preneel结构），输出256或512比特，作者选择256比特版本以与SPHINCS+原有参数兼容。

## 核心成果
1. Streebog实例化的SPHINCS+在主流参数集下性能与SHA-256版本基本持平。
2. 为SPHINCS+的哈希可替换性提供了早期实证，验证了框架的模块化设计优势。

## 与本项目关联
**背景知识**: 与本项目（SPHINCS++Poseidon2）共享"替换SPHINCS+哈希原语"的核心方法论。Kiktenko是SPHINCS+哈希替换最早实例之一，为本项目提供了结构兼容性和性能预期的参考基线。
