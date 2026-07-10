# Machine-Checked Security for XMSS as in RFC 8391 and SPHINCS+

**出处**: CRYPTO 2023
**作者**: Manuel Barbosa, Francois Dupressoir, Benjamin Gregoire, Andreas Huelsing, Matthias Meijers, Pierre-Yves Strub

## 论点
使用EasyCrypt证明助手对XMSS（RFC 8391）和SPHINCS+进行机器验证的安全性证明，修复了此前紧安全证明中存在的漏洞，并首次将形式化验证应用于基于哈希的签名方案。

## 背景
2020年Kudinov等人发现SPHINCS+和XMSS紧安全证明中的漏洞。SPHINCS+的修复已由Huelsing和Kudinov完成，但XMSS的修复需要额外假设——将消息哈希函数建模为随机预言机。同时，密码方案的形式化验证日益重要，但此前尚未应用于XMSS和SPHINCS+这类复杂的分层哈希签名方案。

## 技术路线
使用EasyCrypt证明助手进行形式化验证，构建可重用的EasyCrypt库覆盖哈希函数、数字签名方案、可调哈希函数等基础密码概念。验证了两个方案共享的核心安全证明步骤（WOTS+的PRF安全性和选择消息攻击下的不可伪造性），确认Huelsing-Kudinov证明核心的正确性。整个证明以机器可检查的形式呈现，消除了手动证明的人为错误风险。

## 核心成果
- 首次在EasyCrypt中完成对XMSS和SPHINCS+的形式化安全验证
- 修复了XMSS紧安全证明的漏洞，完善了理论安全基础
- 建立了可重用的EasyCrypt形式化验证库，可支持其他哈希签名方案（如LMS）

## 与本项目关联
**背景知识**: 本项目以SPHINCS+为基础签名方案扩展盲签名协议，SPHINCS+的安全性由该论文提供形式化保证。机器验证的安全性证明增强了整个Fischlin盲签名协议的可信基础。
