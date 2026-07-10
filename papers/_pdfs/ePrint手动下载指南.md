# ePrint 论文手动下载指南

由于 eprint.iacr.org 有 Cloudflare 反爬保护，无法通过脚本自动下载。
以下是最重要的 ePrint 论文及其直接下载链接，请在浏览器中逐个打开下载：

## 核心论文（建议优先下载）

1. **Poseidon2** (AFRICACRYPT 2023) — 项目核心哈希函数
   https://eprint.iacr.org/2023/323.pdf

2. **Hash-Based Blind Signatures** (2025) — 与本项目最接近的工作
   https://eprint.iacr.org/2025/2097.pdf

3. **Blinding Post-Quantum Hash-and-Sign Signatures** (IEEE S&P 2026)
   https://eprint.iacr.org/2025/895.pdf

4. **CAPSS: SNARK-Friendly Post-Quantum Signatures** (2025)
   https://eprint.iacr.org/2025/061.pdf

5. **Monolith: Circuit-Friendly Hash Functions** (2023)
   https://eprint.iacr.org/2023/1025.pdf

6. **Anemoi + Jive Compression Mode** (CRYPTO 2023)
   https://eprint.iacr.org/2022/840.pdf

7. **Rescue-Prime Standard Specification** (2020)
   https://eprint.iacr.org/2020/1143.pdf

8. **ALFOMs: ZK-Friendly Hash Performance/Security Tradeoff** (2025)
   https://eprint.iacr.org/2025/1920.pdf

## 盲签名相关

9. **Katsumata et al. Practical Round-Optimal Blind Signatures** (ASIACRYPT 2023)
   https://eprint.iacr.org/2023/1447.pdf

10. **Tanuki: Blind Signatures from Post-Quantum Group Actions** (ASIACRYPT 2025)
    https://eprint.iacr.org/2025/1100.pdf

11. **Hauck et al. Lattice-Based Blind Signatures, Revisited** (CRYPTO 2020)
    https://eprint.iacr.org/2020/769.pdf

12. **Beullens et al. Lattice Blind Signatures** (CCS 2023)
    https://eprint.iacr.org/2023/077.pdf

## SPHINCS+相关

13. **SPHINCS-α** (2022)
    https://eprint.iacr.org/2022/059.pdf

14. **SPHINCS+C** (IEEE S&P 2023 ePrint版)
    https://eprint.iacr.org/2024/320.pdf

## STARK/ZK相关

15. **STARKPack: Amortization Techniques** (2024)
    https://eprint.iacr.org/2024/661.pdf

16. **PLONK** (2019)
    https://eprint.iacr.org/2019/953.pdf

17. **Post-Quantum Privacy Pass** (2023)
    https://eprint.iacr.org/2023/414.pdf

## 竞争方案

18. **Loquat** (CRYPTO 2024)
    https://eprint.iacr.org/2024/1027.pdf

19. **Sphinx-in-the-Head** (2024)
    https://eprint.iacr.org/2024/442.pdf

20. **Spinel** (2026)
    https://eprint.iacr.org/2026/221.pdf

21. **Solana STARK+PQC Verification** (2025)
    https://eprint.iacr.org/2025/1741.pdf

---

## 下载方式

### 方法一：浏览器直接打开链接
点击上述链接，浏览器会自动打开PDF，然后 Ctrl+S 保存

### 方法二：使用 wget（如果可用）
```bash
wget -O paper_name.pdf "https://eprint.iacr.org/YYYY/NNN.pdf"
```

### 方法三：Python requests
```python
import requests
url = "https://eprint.iacr.org/2023/323.pdf"
r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
with open("paper.pdf", "wb") as f:
    f.write(r.content)
```

下载后请将所有PDF文件放入 `papers/_pdfs/` 目录。
