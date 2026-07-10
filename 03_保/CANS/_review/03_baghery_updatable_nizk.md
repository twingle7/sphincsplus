# Updatable NIZKs from Non-Interactive Zaps

**出处**: CANS 2022
**作者**: Karim Baghery, Navid Ghaedi Bardeh

## 论点
利用非交互Zap（NI zap）可以构造具有可更新声音性（Updatable Soundness）的NIZK论证系统，避免对可信第三方的依赖。

## 背景
传统NIZK需要公共参考串（CRS），CRS的生成依赖可信第三方。子版本零知识（Sub-ZK）允许验证者选择CRS但仍需信任。可更新CRS的NIZK允许多方贡献随机性，任何一方只要诚实则系统安全。此前尚无同时满足可更新、通用、简洁CRS且不需要随机谕言机的NIZK构造。

## 技术路线
以Bellare-Fuchsbauer-Scafuro（ASIACRYPT 2016）的构造为基础：将CRS定义为双线性群中的知识假设元组，并使用NI zap证明"要么语句有见证，要么CRS的陷门已知"。创新在于将该构造的安全定义扩展为可更新声音性。编译器将NI zap与密钥可更新签名结合，定义OR语言实现可更新模拟声音性和可提取性。实例化使用Groth-Ostrovsky-Sahai和Fuchsbauer-Orru的NI zap方案。

## 核心成果
1. 首个具有简洁可更新CRS的NIZK论证系统（无需随机谕言机）。
2. 同时实现子版本零知识和可更新模拟声音性/可提取性。
3. CRS验证和更新开销仅为少量指数运算和配对检查，与底层NI zap相比不增加渐近复杂度。

## 与本项目关联
方法论参考：NIZK的可更新CRS设计与Fischlin协议中公开可验证性的需求相呼应，更新机制对于分布式信任设置的后量子ZK系统设计有参考意义。
