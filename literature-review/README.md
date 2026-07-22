# Literature Review: Post-Quantum Blind Signatures via SPHINCS+ & Fischlin

**Status**: 🔄 In Progress (Phase 3 of 5)
**Generated**: 2026-07-22
**Review type**: Systematic survey covering 8 dimensions × 2 search sources

## Project Scope

A survey of post-quantum blind signatures with focus on:
- SPHINCS+ hash-based signatures
- Fischlin blind signature framework
- Poseidon2 ZK-friendly hash (Goldilocks field)
- Winterfell STARK zero-knowledge proofs
- Hash-based blind signature co-design

## Dimensions Covered

| # | Dimension | Search Status |
|---|-----------|--------------|
| 1 | PQ Blind Signatures | ✅ Complete |
| 2 | SPHINCS+ / Hash-based | ✅ Complete |
| 3 | Fischlin Protocol | ✅ Complete |
| 4 | ZK-Friendly Hash (Poseidon2) | ✅ Complete |
| 5 | STARK + Signatures | ⚠️ Partial (noise from generic "proof system" results) |
| 6 | Cross: PQ + Blind/Anonymous Credentials | ✅ Complete |
| 7 | Cross: Hash + STARK | ✅ Complete |
| 8 | Cross: Fischlin + PQ | ✅ Complete |

## Key Papers Found (Priority Reading)

### 🔴 CRITICAL — Directly Related to This Project

1. **"Blinding Post-Quantum Hash-and-Sign Signatures"** (IEEE S&P 2026)
   Bouillaguet, Feneuil, Maire, Rivain, Sauvage, Vergnaud
   → Fischlin framework that compiles ANY PQ hash-and-sign into blind signature
   → Directly confirms viability of SPHINCS+ → Fischlin approach
   DOI: 10.1109/SP63933.2026.00032

2. **"Hash-Based Blind Signatures: First Steps"** (ePrint 2025)
   Herranz, Louiso
   → First exploration of hash-based blind signatures specifically
   → May overlap with your contribution; read carefully to differentiate

### 🟠 HIGH — Foundational & Related Work

3. **"The SPHINCS+ Signature Framework"** (CCS 2019)
   Bernstein et al. — 401 citations
   → The SPHINCS+ scheme specification

4. **"Poseidon2: A Faster Version of the Poseidon Hash Function"** (AFRICACRYPT 2023)
   Grassi, Khovratovich, Schofnegger — 24 citations
   → Poseidon2 design (your hash backend)

5. **"Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"** (2019)
   Grassi et al. — 71 citations
   → Original Poseidon hash for ZK proofs

6. **"Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal"** (CCS 2023)
   Beullens, Lyubashevsky, Nguyen, Seiler — 28 citations
   → Current SOTA round-optimal Fischlin-style blind sig (lattice-based)

7. **"A New Framework for More Efficient Round-Optimal Lattice-Based (Partially) Blind Signature"** (CRYPTO 2022)
   del Pino, Katsumata — 43 citations
   → Fischlin framework via trapdoor sampling

8. **"Practical Post-Quantum Signatures for Privacy"** (CCS 2024)
   Argo et al. — 16 citations
   → PQ blind sigs, group sigs, anonymous credentials

9. **"A Survey on Exotic Signatures for Post-quantum Blockchain"** (ACM Computing Surveys 2022)
   Buser et al. — 40 citations
   → Comprehensive survey covering PQ blind/ring/adaptor signatures

10. **"On Advances of Anonymous Credentials - From Traditional to Post-Quantum"** (2025)
    Chathurangi, Li, Foo — 4 citations
    → Recent survey on PQ anonymous credentials

## PDF Download Status

| Paper | Status | Reason |
|-------|--------|--------|
| Bouillaguet 2026 (IEEE S&P) | ❌ Not downloaded | IEEE paywall, need arXiv version |
| Herranz 2025 (ePrint) | ❌ Not downloaded | Need to locate ePrint ID |
| Bernstein 2019 (CCS) | ❌ Not downloaded | ACM paywall; arXiv: 1910.08235 might work |
| Grassi 2023 (Poseidon2) | ❌ Not downloaded | Springer paywall |
| Beullens 2023 (CCS) | ❌ Not downloaded | ACM paywall; check ePrint |
| Others | ❌ Not downloaded | Mixed paywall/OA |

**Automated PDF download is blocked** for ACM, IEEE, and Springer papers (HTTP 403).
arXiv/ePrint-hosted papers should work via `ingest_paper_fulltext`.

## Next Steps

### 🔧 For YOU (User) — One-time Setup

1. **Get a free Semantic Scholar API key** (removes rate limit):
   → https://www.semanticscholar.org/product/api
   → Add to: `D:\Desktop\sphincsplus\.mcp.json`
   ```json
   "_semantic_scholar_disabled": {
     "env": {
       "SEMANTIC_SCHOLAR_API_KEY": "your-key-here"
     }
   }
   ```
   → Then restart Claude Code

2. **Download key papers manually** (if you need PDFs):
   - Most papers have free preprints on arXiv or ePrint (https://eprint.iacr.org)
   - Save to: `D:\Desktop\sphincsplus\literature-review\papers\`
   - You can then use `ingest_paper_fulltext` with `localPdfPath` for automated extraction

### 🤖 For Claude Code (after API key setup) — Continue Automation

1. Resume BibTeX generation for remaining papers
2. Search arXiv IDs for paywalled papers
3. Download OA PDFs
4. Extract full-text analysis (claims, methods, limitations)
5. Write the survey using ARS deep-research or manual organization

## Files

| File | Description |
|------|-------------|
| `bibliography.bib` | BibTeX entries for confirmed key papers (15 entries) |
| `papers_by_dimension.json` | Paper classification index with key papers |
| `papers/` | Downloaded PDFs (currently empty — see PDF Download Status) |
| `fulltext/` | Extracted full-text JSON (currently empty) |
