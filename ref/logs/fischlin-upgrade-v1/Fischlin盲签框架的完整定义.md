<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# 给出Fischlin盲签框架的完整定义

下面给出密码学文献里对 **Fischlin** 盲签框架的标准化、形式完整的核心定义：它先让签名者对消息承诺签名，再让用户用 NIZK 证明“该承诺确实打开到消息 $m$，且其上已有有效签名”，从而得到最终盲签名。[^1][^2]
后续文献在复述该框架时常采用一个简化版本，并明确说明省去了 Fischlin 原方案中为达到强不可伪造性而加入的额外技巧；下面给出的就是这个最常用的核心定义。[^1]

## 抽象定义

形式上，盲签名方案是四元组 $(Gen,S,U,Vrfy)$，其中 $Gen$ 和 $Vrfy$ 是 PPT 算法，$S$ 与 $U$ 是交互式 PPT 算法。[^1]
当签名者 $S$ 持有秘密钥匙 $SK$，用户 $U$ 持有公钥 $PK$ 和消息 $m$ 时，二者交互执行并使用户输出签名 $\sigma$，记作 $\sigma \leftarrow \langle S_{SK}, U_{PK}(m)\rangle$；若用户中止，则其输出为 $\bot$。[^1]
正确性要求：对任意由 $Gen(1^k)$ 产生的 $(PK,SK)$ 和任意消息 $m$，只要交互未中止，就必须有 $Vrfy_{PK}(m,\sigma)=1$。[^1]

## 组成部件

Fischlin 框架以一个普通签名方案 $\Pi'=(Gen',Sign',Vrfy')$、一个完美绑定承诺方案 $Com$、一个语义安全公钥加密方案，以及一个 NIZK 证明系统为底层原语。[^2][^1]
它工作在 CRS 模型下，其中公共参考串包含加密公钥 $pk_E$ 和 NIZK 参考串 $\rho$，而盲签名自身的公私钥则直接由普通签名方案生成，即运行 $Gen'(1^k)$ 得到 $(pk',sk')$。[^1]
后续论文通常把这个范式概括为：**签署承诺，再证明其可打开到消息** 的 round-optimal blind-signature framework。[^2]

## 协议定义

签发阶段第 1 步，用户计算 $com \leftarrow Com(m)$ 并把 $com$ 发给签名者；第 2 步，签名者计算 $\sigma' \leftarrow Sign'_{sk'}(com)$ 并把 $\sigma'$ 返回给用户。[^1]
第 3 步，用户先验证 $Vrfy'_{pk'}(com,\sigma')=1$，若失败则中止；若成功，则计算密文 $C \leftarrow E_{pk_E}(com\|\sigma')$，并生成一个 NIZK 证明 $\pi$，证明存在随机性 $\omega_1,\omega_2$、承诺 $com$ 和内部签名 $\sigma'$，使得 $com=Com(m;\omega_1)$、$C=E_{pk_E}(com\|\sigma';\omega_2)$ 且 $Vrfy'_{pk'}(com,\sigma')=1$。[^1]
因此，最终盲签名定义为 $(C,\pi)$；验证算法在输入消息 $m$ 与候选签名 $(C,\pi)$ 时，只需检查 $\pi$ 是否是关于语句“$(m,C,pk_E,pk')\in L$”的有效证明，其中 $L$ 正是上述存在性关系定义的 NP 语言。[^1]

对应地，可把语言 $L$ 明确写成

$$
L=\left\{(m,C,pk_E,pk'):\exists \omega_1,\omega_2,com,\sigma' \text{ s.t. }
\begin{array}{l}
com=Com(m;\omega_1),\\
C=E_{pk_E}(com\|\sigma';\omega_2),\\
Vrfy'_{pk'}(com,\sigma')=1
\end{array}
\right\}.
$$

这一定义正是 Fischlin 框架的“证明一个已签名承诺能打开到消息 $m$”这一核心结构。[^2][^1]

## 安全性质

该框架的第一类安全性是 blindness：恶意签名者即使与两个诚实用户分别围绕消息 $m_0,m_1$ 进行交互，也不应能判断最终拿到的两个消息/签名结果分别对应哪次会话。[^3][^1]
第二类安全性是 unforgeability，而在盲签名里通常采用 one-more 形式来表述：若攻击者至多完成 $\ell$ 次与诚实签名者的签发交互，就不能输出 $\ell+1$ 个针对两两不同消息的有效签名。[^4][^1]
对 Fischlin 框架而言，blindness 依赖于承诺、加密与 NIZK 不泄露消息且不允许会话关联，而 unforgeability 的证明思路则是把任何对盲签名的伪造归约为对底层普通签名方案 $\Pi'$ 的伪造。[^1]


