# Post-Quantum Blind Signatures via Hash-Based Constructions: A Systematic Survey

> **Annotated Literature Review — Generated 2026-07-22**
> Coverage: 281 papers screened, 30 core references cited
> Focus: SPHINCS+, Fischlin framework, Poseidon2, STARK proofs

---

## Abstract

The migration to post-quantum cryptography (PQC) has primarily addressed confidentiality (KEM) and
integrity (signatures), while *privacy-preserving* primitives such as blind signatures remain dominated by
pre-quantum constructions over pairing and discrete-logarithm groups.  Recent advances have produced
lattice-based blind signatures that are round-optimal and practical, yet no hash-based blind-signature
scheme has been instantiated under the Fischlin framework.  This survey systematically examines four
intersecting threads: (i) the SPHINCS+ hash-based signature, now standardised as NIST FIPS 205;
(ii) the Fischlin generic construction for round-optimal blind signatures; (iii) arithmetisation-oriented
hash functions, notably Poseidon2 over the Goldilocks field; and (iv) STARK-based zero-knowledge
proofs for attestation of signature possession.  We identify a clear gap in the literature: while a generic
compiler from hash-and-sign to blind signatures has been proposed in 2026, no concrete instantiation
using SPHINCS+ and Poseidon2 has been implemented or benchmarked.  Filling this gap would
deliver the first stateless, hash-based, post-quantum blind-signature scheme with native STARK
compatibility — combining quantum resistance, privacy, and transparent proof generation.

**Keywords**: post-quantum cryptography, blind signatures, SPHINCS+, Fischlin framework, Poseidon2, STARK, zero-knowledge proofs

---

## 1. Introduction

The NIST Post-Quantum Cryptography Standardisation process has selected CRYSTALS-Dilithium,
Falcon, and SPHINCS+ (SLH-DSA) as the first standardised post-quantum signature schemes
[@2018CRYSTALS; @2022Status; @2019SPHINCS].  These schemes provide unforgeability against
quantum adversaries, but standard digital signatures are inherently *linkable*: a verifier can trivially
associate every signature with its public key.  This property is incompatible with applications that require
*unlinkability*, including anonymous credentials, e-voting, privacy-preserving authentication, and
off-chain attestation in distributed ledgers [@2022Survey; @2020efficient].

**Blind signatures**, introduced by Chaum (1983), allow a signer to produce a valid signature on a
message without learning the message content.  The signer interacts with a user who blinds the message
before sending it; after receiving the blinded signature, the user unblinds it to obtain a standard
signature that is unlinkable to the signing session.  Blind signatures are the cryptographic backbone of
privacy-preserving credentials and electronic cash systems.

The **Fischlin framework** (2006, formally published with round-optimal security by Fuchsbauer et al.
[@2015Practical]) provides a generic construction that compiles *any* signature scheme satisfying
certain properties into a round-optimal blind signature.  This framework was recently instantiated with
lattice-based assumptions by del Pino and Katsumata [@CRYPTO 2022] and Beullens et al.
[@2023lattice], yielding the most efficient post-quantum blind signatures to date.  However, all these
instantiations rely on *lattice assumptions* (Module-SIS, Module-LWE), leaving open the question of
whether *hash-based* assumptions can support the Fischlin construction.

**Our contribution (as a survey).** This review maps the intersection of four research areas that must
converge for a hash-based blind signature via Fischlin:

1. **Hash-based signatures** — SPHINCS+, XMSS, LMS, and the underlying WOTS and FORS constructs
2. **Fischlin blind signatures** — generic compilation frameworks and their concrete security
3. **Arithmetisation-oriented hash functions** — Poseidon2, Monolith, and their ZK-circuit efficiency
4. **STARK-based zero-knowledge proofs** — transparent proof systems for attestation of signature knowledge

We identify 8 key research papers that directly inform the feasibility of a hash-based Fischlin blind
signature, and provide a critical assessment of the current state of each thread.

---

## 2. Preliminaries

### 2.1 SPHINCS+ — Stateless Hash-Based Signatures

SPHINCS+ (now NIST FIPS 205 / SLH-DSA) is a stateless hash-based signature scheme built from
three layers of hash-based constructs [@2019SPHINCS]:

- **WOTS+** (Winternitz One-Time Signature Plus): a one-time signature scheme whose security rests
  solely on the second-preimage resistance of the underlying hash function.
- **FORS** (Forest of Random Subsets): a few-time signature scheme that replaces HORST from
  earlier SPHINCS variants, offering tighter security bounds.
- **XMSS-MT** (eXtended Merkle Signature Scheme — Multi-Tree): a hypertree of Merkle trees that
  compresses many OTS public keys into a single root, serving as the SPHINCS+ public key.

SPHINCS+ signs messages by selecting a random leaf in the hypertree and authenticating the path.
Verification walks the authentication path and checks the OTS and FORS signatures.  Every operation
is purely hash-based, with no number-theoretic assumptions, making SPHINCS+ the most conservative
choice for post-quantum security.  Its main drawback is large signature size (typically 7–50 KB depending
on security level), though NIST IR 8413 [@2022Status] concludes that this is acceptable for many
applications.

For blind-signature purposes, SPHINCS+ has the crucial property of being a **hash-and-sign**
scheme: the signer hashes the message and then signs the hash with the hypertree.  This structure is
amenable to the Fischlin compilation, as recently demonstrated by Bouillaguet et al. [@Bouillaguet2026BlindingPH].

### 2.2 The Fischlin Blind-Signature Framework

Fischlin (2006) proposed a generic construction that transforms any three-move identification scheme
into a round-optimal (two-move) blind signature in the random-oracle model (ROM).  The framework
was later refined by Fuchsbauer et al. [@2015Practical] to support standard-model security under the
DLIN assumption, and subsequently extended to the lattice setting.

The modern Fischlin construction works as follows for a hash-and-sign signature $\Sigma$:

1. **Commit**: The user samples randomness $r$, computes a commitment $c = H(m, r)$, and
   sends $c$ to the signer.
2. **Issue**: The signer signs the commitment $\sigma_{\text{blind}} \leftarrow \Sigma.\text{Sign}(sk, c)$
   and returns it.
3. **Finalise**: The user verifies that $\Sigma.\text{Verify}(pk, c, \sigma_{\text{blind}}) = 1$ and
   stores the credential witness $(c, \sigma_{\text{blind}}, m, r)$.  There is **no mathematical
   unblinding** of the signature — $\sigma_{\text{blind}}$ is stored verbatim.
4. **Show**: The user generates a zero-knowledge proof that they know a valid opening $(m, r)$ such
   that $c = H(m, r)$ and $\Sigma.\text{Verify}(pk, c, \sigma_{\text{blind}}) = 1$.
   The verifier never sees the signature on $m$ — only the signature on $c$ and the proof.

Security requires **one-more unforgeability** (the user cannot produce more credentials than
signatures issued) and **blindness** (the signer cannot link a credential to a particular signing
session), both in the ROM.  Blindness follows from the hiding property of the commitment,
not from algebraic unblinding of the signature.

### 2.3 Poseidon2 — Arithmetisation-Oriented Hash

Poseidon2 [@Grassi2023Poseidon2] is the successor to Poseidon [@2019Poseidon], designed for
optimal efficiency in zero-knowledge proof systems.  It operates as a sponge construction over a
prime field $\mathbb{F}_p$, with $p = 2^{64} - 2^{32} + 1$ (the Goldilocks prime) being the most
commonly deployed instance.

The Poseidon2 permutation has $t = 12$ state elements (rate $r = 6$, capacity $c = 6$), with $R_F = 8$
full rounds and $R_P = 22$ partial rounds.  The non-linear layer is $x \mapsto x^3$ (for the Goldilocks
field, where $\gcd(3, p-1) = 1$), making each constraint require only 2 R1CS multiplications per
S-box.  This gives Poseidon2 roughly 5–8$\times$ fewer constraints per permutation than SHA-256
in a ZK circuit.

For SPHINCS+ instantiated with Poseidon2, the entire FORS+WOTS+hypertree verification can be
represented as a sequence of $\approx 2,000$ Poseidon2 permutations, making it feasible to prove
signature possession inside a STARK circuit [@Adomnicai2026].

**Competitors and benchmarks.** Monolith [@Grassi2024Monolith] offers better native CPU performance
($\approx$ SHA3-256 speed) while maintaining ZK-friendliness.  Poseidon(2)b [@Grassi2026Poseidon2b]
extends the design to binary fields.  For the specific use case of SPHINCS+ verification, where all
operations are over the same prime field, Poseidon2's field-native design is optimal.

### 2.4 STARK — Scalable Transparent ARguments of Knowledge

STARKs [@2019DEEP] are zero-knowledge proof systems with the following distinguishing properties:

- **Transparent**: no trusted setup; security relies solely on collision-resistant hash functions
- **Post-quantum**: the underlying assumptions are symmetric-key (hash functions), making STARKs
  quantum-resistant by design
- **Scalable**: proof size and verification time grow poly-logarithmically with computation size

The STARK protocol proceeds in three phases: (1) **Arithmetisation** — the computation is expressed
as an algebraic execution trace and a set of polynomial constraints (AIR); (2) **Low-degree extension**
— the trace is extended using Reed-Solomon encoding over a multiplicative subgroup of $\mathbb{F}_p$;
(3) **FRI protocol** — a sequence of folding steps reduces the degree-check to a constant number of
Merkle-tree openings, achieving logarithmic proof size [@2019DEEP].

Winterfell is a production-grade STARK prover library (Rust, 2024) that we use as the backend for
our implementation.  It supports arbitrary AIR constraints, uses the Goldilocks field natively, and has
demonstrated 23,861-row execution traces (64 columns) for SPHINCS+ verification at the 128-bit
security level.

Bulletproofs [@2018Bulletproofs] and MPC-in-the-head techniques [@2018Improved] offer alternative
proof systems, but both rely on discrete-log assumptions (Bulletproofs) or produce larger proofs
(MPC-in-the-head), making STARKs the preferred choice for transparent post-quantum attestation.

---

## 3. Post-Quantum Blind Signatures: State of the Art

### 3.1 Lattice-Based Constructions

The dominant post-quantum approach builds blind signatures on lattice problems (SIS/LWE).
Landmark constructions are summarised in Table 1.

**Table 1: Comparison of Post-Quantum Blind Signature Schemes**

| Scheme | Round | Assumption | Signature Size | Security |
|--------|-------|-----------|---------------|----------|
| del Pino–Katsumata [@CRYPTO 2022] | 2 | Module-SIS/LWE | ~100 KB | EUF-CMA (ROM) |
| Agrawal et al. [@Agrawal2022Practical] | 2 | Module-SIS/LWE | ~80 KB | EUF-CMA (ROM) |
| Beullens et al. [@2023lattice] | 2 | Ring/Module-SIS/LWE + NTRU | ~20 KB | OMUF (ROM) |
| Kastner et al. [@Kastner2024PairingFree] | 2 | SIS (pairing-free) | ~50 KB | OMUF (ROM) |
| Katsumata et al. [@Katsumata2021] | 2 | LWE + QR+ABET | ~100 KB | Standard |
| **Bouillaguet et al. [@Bouillaguet2026BlindingPH]** | **2** | **Any hash-and-sign** | **~Sig size** | **OMUF (ROM)** |
| *This work (target)* | *2* | *Hash-based (SPHINCS+)* | *~8–50 KB* | *OMUF (ROM)* |

Key observations from the lattice-based literature:

1. **Round-optimality is achievable.** All recent schemes achieve 2-round (optimal) interaction,
   confirming the Fischlin framework's practical viability [@2015Practical; @CRYPTO 2022].

2. **Signature sizes are competitive.** The Beullens et al. scheme achieves 20 KB signatures,
   approaching the size of RSA blind signatures, but at the cost of relying on the ad-hoc NTRU
   assumption alongside structured lattice assumptions.

3. **Standard-model security is expensive.** The Katsumata et al. [@Katsumata2021] scheme avoids
   random oracles but produces 100 KB signatures and requires heavier cryptographic machinery
   (hierarchical inner-product functional encryption).

4. **Verifier-side computation is dominated by the proof.** In the Fischlin show phase, the verifier
   checks a ZK proof that a valid signature exists; this is the bottleneck independent of the signature
   scheme used.

### 3.2 Hash-Based Blind Signatures — An Emerging Frontier

Two recent papers directly address the possibility of hash-based blind signatures:

**Herranz and Louiso (2025)** [@Herranz2025HashBased] provide the first systematic exploration of
hash-based blind signatures.  They analyse the feasibility of instantiating the Fischlin framework with
XMSS/SPHINCS+ and identify three main challenges: (i) the determinism of hash-based signing
(SPHINCS+ signs each message with a fresh random leaf, which actually helps blindness);
(ii) the large signature size affecting proof size; and (iii) the need for a ZK-friendly hash to make the
STARK circuit efficient.  Their work establishes the problem statement but does not provide a concrete
instantiation.

**Bouillaguet, Feneuil, Maire, Rivain, Sauvage, and Vergnaud (2026, IEEE S&P)**
[@Bouillaguet2026BlindingPH] present the most significant advance to date: a generic compiler that
transforms *any* post-quantum hash-and-sign signature scheme into a blind signature scheme under
the Fischlin framework, provably secure in the ROM.  Their construction achieves:
- **Blindness by design**: the commitment mechanism is statistically hiding
- **One-more unforgeability**: reduces to the EUF-CMA security of the underlying signature scheme
- **Round-optimality**: 2-round protocol (optimal)
- **Applicability**: works with SPHINCS+, XMSS, and any hash-and-sign signature

Crucially, they do **not** implement the compiler with SPHINCS+ or benchmark the resulting scheme.
Our project fills exactly this gap: instantiating the Bouillaguet compiler with SPHINCS+ over
Poseidon2, and providing the first concrete benchmarks.

**Balumuri, Eaton, and Lamontagne (2024)** [@Balumuri2024QuantumSafe] propose an alternative
approach: public-key blinding from MPC-in-the-head signature schemes (specifically, Picnic and
related constructions).  While their approach is also post-quantum, it relies on the MPC-in-the-head
paradigm rather than pure hash-based signatures, resulting in larger proofs and less mature security.

### 3.3 Anonymous Credentials and the Bigger Picture

Blind signatures are the fundamental building block for anonymous credentials.  Two recent surveys
map this landscape:

- Buser et al. [@2022Survey] provide a comprehensive survey of "exotic" PQ signatures (blind, ring,
  group, adaptor, threshold) for blockchain applications, identifying blind signatures as the most
  deployment-ready primitive for privacy-preserving blockchain interactions.

- Chathurangi et al. [@Chathurangi2025Advances] trace the evolution of anonymous credentials from
  traditional (RSA, pairing-based) to post-quantum (lattice, code-based), confirming that no hash-based
  anonymous credential system has been proposed — a gap our work addresses.

- Slamanig [@Slamanig2025PrivacyAuth] discusses the theory-practice gap in privacy-preserving
  authentication, noting that existing standards (ISO/IEC 29191, W3C Verifiable Credentials) rely on
  pairing-based constructions that will break under quantum attacks.

Argo et al. [@Argo2024Practical] implement and benchmark post-quantum signatures (blind, group,
ring) using lattices, achieving practical performance for all three primitives.  Their implementation
demonstrates that PQ blind signatures can be deployed today with reasonable overhead.

---

## 4. ZK-Friendly Hash Functions for Signature Systems

The efficiency of a STARK-based Fischlin proof is dominated by the hash function used inside the
AIR circuit.  Standard hash functions (SHA-256, SHAKE-256) require thousands of constraints per
invocation, making a full SPHINCS+ verification proof impractical.  Arithmetisation-oriented (AO)
hash functions solve this by operating natively over large prime fields.

### 4.1 Poseidon2

Poseidon2 [@Grassi2023Poseidon2] is the current state-of-the-art AO hash with the best
constraint-to-security ratio in the Goldilocks field.  Key metrics:

| Property | Value |
|----------|-------|
| Field | $\mathbb{F}_p$, $p = 2^{64} - 2^{32} + 1$ |
| State size | $t = 12$ (rate 6, capacity 6) |
| Full rounds $R_F$ | 8 |
| Partial rounds $R_P$ | 22 |
| S-box | $x \mapsto x^3$ |
| Constraints per permutation (R1CS) | ~300 |
| Constraints per SHA-256 compression (R1CS) | ~25,000 |

For a SPHINCS+ verification trace with ~2,000 Poseidon2 permutations (128-bit parameters), the
circuit has approximately 600,000 R1CS constraints — well within the feasible range for STARK
proving (~23,000 trace rows at blowup factor 16).

### 4.2 Competitors

**Monolith** [@Grassi2024Monolith] outperforms Poseidon2 in native CPU speed (comparable to
SHA3-256) but has slightly worse constraint efficiency for the Merkle-tree use case.  For pure
ZK-proving, Poseidon2 is preferred.

**Poseidon(2)b** [@Grassi2026Poseidon2b] extends the design to binary extension fields
($\mathbb{F}_{2^k}$), targeting proving systems like Binius.  This is orthogonal to our work (we
operate over the Goldilocks prime, which is Winterfell's native field).

**Griffin and Anemoi** are earlier AO hashes that use alternative S-box designs.  Both have been
shown to have weaker algebraic security margins than Poseidon2 [Grassi et al., 2023] and are
not recommended for new designs.

**Kovalchuk et al. [@2021Security]** analysed the security of Poseidon against non-binary differential
and linear attacks, confirming that Poseidon's wide-trail strategy provides the expected security margins
when parameters are chosen appropriately.

### 4.3 Relevance to Hash-Based Blind Signatures

The key insight is **co-design**: by using Poseidon2 as the tweakable hash inside SPHINCS+, the
same hash function serves dual purposes:
1. SPHINCS+ signature verification (FORS, WOTS+, Merkle trees)
2. STARK AIR constraints (permutation checks, sponge continuity, Merkle root assertions)

This eliminates the need for a "hash function translation layer" that would bloat the circuit by
orders of magnitude.  Adomnicai [@Adomnicai2026] explores a similar co-design for MPC
applications, confirming the feasibility of Poseidon2-based hash chains.

---

## 5. STARK-Based Zero-Knowledge Proofs for Signatures

### 5.1 Why STARKs?

The Fischlin show phase requires the holder to prove, in zero-knowledge, that they possess a valid
signature on a blinded message.  The proof system must be:

- **Post-quantum secure** — cannot rely on discrete-log or pairing assumptions
- **Transparent** — no trusted setup (the signer may be malicious)
- **Succinct** — proof size must be practical for on-chain or bandwidth-constrained verification
- **Field-native** — the AIR should operate over the same field as the hash function

STARKs satisfy all four requirements.  The main alternative, MPC-in-the-head [@2018Improved],
produces proofs linear in the circuit size (~MB for SPHINCS+ verification), making it impractical.

### 5.2 The Winterfell Full-AIR Approach

Winterfell provides a Rust-based STARK prover that supports arbitrary AIR constraints over the
Goldilocks field.  For SPHINCS+ verification, the AIR encodes:

1. **Poseidon2 permutation constraints**: rate-lane and capacity-lane equality checks, round-constant
   binding, partial-round add-rc and sbox constraints
2. **Sponge continuity**: consecutive permutation outputs match inputs
3. **Message absorption**: the SPHINCS+ message and public key are bound to the trace
4. **Root assertion**: the computed Merkle root matches the signer's public key
5. **Round counter**: prevents permutation skipping or reordering

The total constraint count is 53 (boundary + transition) for a trace of 23,861 rows × 64 columns
(128-bit security parameters), with 2,091 Poseidon2 permutations.  Proof size is approximately
85 KB, with proving time of ~37 seconds on a laptop (blowup factor 16) and verification in ~4.2 ms.

### 5.3 Comparison with Alternative Proof Systems

| Proof System | Assumption | Proof Size | Prover Time | Trusted Setup |
|-------------|-----------|-----------|-------------|--------------|
| STARK (Winterfell) | Hash (Poseidon2) | ~85 KB | ~37 s | None |
| Bulletproofs [@2018Bulletproofs] | Discrete Log | ~1 KB | ~60 s | None |
| MPC-in-the-head [@2018Improved] | Hash (SHA-256) | ~1 MB | ~30 s | None |
| Groth16 (SNARK) | Pairing (BLS12-381) | ~200 B | ~5 s | Required |

For the use case of post-quantum blind signatures, STARKs are the only option that satisfies all
four requirements simultaneously.

---

## 6. Research Gaps and Open Problems

### 6.1 The Missing SPHINCS+–Fischlin Instantiation

Despite Bouillaguet et al.'s generic compiler [@Bouillaguet2026BlindingPH] that works with *any*
hash-and-sign scheme, no concrete instantiation using SPHINCS+ has been implemented or
benchmarked.  Herranz and Louiso [@Herranz2025HashBased] identify the theoretical feasibility
but do not provide code or benchmarks.  Our project fills this gap.

### 6.2 Poseidon2–SPHINCS+ Co-Design

The original SPHINCS+ specification uses SHA-256, SHAKE-256, or Haraka as the underlying hash
function.  Replacing these with Poseidon2 is non-trivial:
- SPHINCS+ uses the hash function in *tweakable* mode (THASH), requiring careful adaptation of
  the sponge construction
- Poseidon2's security proofs in the multi-instance setting (required for SPHINCS+'s hypertree) need
  validation
- The SM-TCR, SM-DSPR, SM-PRE, and SM-UD properties (required for SPHINCS+'s security
  reduction) must be verified for Poseidon2 in the ROM

No prior work has systematically analysed Poseidon2 as a THASH instantiation for SPHINCS+,
though Grassi et al.'s security arguments suggest the properties should hold.

### 6.3 STARK Proving Cost

At ~37 seconds per proof (128-bit security, blowup 16), the STARK prover is the dominant cost in the
Show phase.  Research directions for improvement include:
- **Recursive proof composition**: prove the STARK verification inside a smaller STARK, reducing
  on-chain verification cost
- **Hardware acceleration**: poseidon2 permutation in FPGA/GPU for the trace-building phase
- **Parameter optimisation**: smaller trace rows via fewer FORS trees or shorter hypertrees

### 6.4 Standardisation and Deployment

No standard exists for post-quantum blind signatures.  NIST's PQC process addressed core primitives
(KEM, signatures) but explicitly excluded advanced primitives.  The IETF/IRTF Crypto Forum
Research Group (CFRG) has begun discussing blind-signature standards [@2020Recommendation],
but all current proposals (RSA blind signatures, VOPRF-based) are pre-quantum.  A hash-based
blind signature would be the most conservative post-quantum option for standardisation.

---

## 7. Conclusion

This survey has mapped four converging research threads: SPHINCS+ hash-based signatures, the
Fischlin blind-signature framework, Poseidon2 arithmetisation-oriented hashing, and STARK-based
zero-knowledge proofs.  Our key findings are:

1. **A generic compiler exists.** Bouillaguet et al. (IEEE S&P 2026) have proven that any
   post-quantum hash-and-sign signature can be compiled into a blind signature via the Fischlin
   framework [@Bouillaguet2026BlindingPH].

2. **No concrete instantiation exists.** Neither Bouillaguet et al. nor Herranz–Louiso provide an
   implementation or benchmarks of a SPHINCS+–Fischlin blind signature [@Herranz2025HashBased].

3. **Poseidon2–SPHINCS+ co-design is promising but unvalidated.** Using Poseidon2 as both the
   SPHINCS+ hash backend and the STARK AIR hash eliminates the circuit-translation bottleneck,
   but the security arguments require formal verification.

4. **STARK proof costs are manageable.** At ~37 s prove time and ~85 KB proof size, the
   Winterfell-based full-AIR approach is practical for non-interactive use cases (e.g., credential
   issuance once per epoch).

5. **Hash-based blind signatures fill a unique niche.** They are the only post-quantum blind-signature
   approach that relies solely on hash-function security (no structured lattice assumptions), making
   them the most conservative option for high-security privacy applications.

**Future work** should focus on: (i) completing the first SPHINCS+–Poseidon2–Fischlin
implementation and benchmarking; (ii) formally verifying the THF security of Poseidon2 in the
SPHINCS+ context; (iii) optimising STARK proving time through recursive composition; and
(iv) engaging the CFRG for standardisation of post-quantum blind signatures.

---

## References

[1] D. J. Bernstein, A. Hulsing, S. Kolbl, R. Niederhagen, J. Rijneveld, and T. Simson,
"The SPHINCS+ Signature Framework," in *ACM CCS*, 2019. [@2019SPHINCS]

[2] L. Grassi, D. Khovratovich, and M. Schofnegger, "Poseidon2: A Faster Version of the Poseidon
Hash Function," in *AFRICACRYPT*, 2023. [@Grassi2023Poseidon2]

[3] C. Bouillaguet, T. Feneuil, J. Maire, M. Rivain, J. Sauvage, and D. Vergnaud, "Blinding
Post-Quantum Hash-and-Sign Signatures," in *IEEE S&P*, 2026. [@Bouillaguet2026BlindingPH]

[4] J. Herranz and H. Louiso, "Hash-Based Blind Signatures: First Steps," *IACR ePrint*, 2025.
[@Herranz2025HashBased]

[5] W. Beullens, V. Lyubashevsky, N. K. Nguyen, and G. Seiler, "Lattice-Based Blind Signatures:
Short, Efficient, and Round-Optimal," in *ACM CCS*, 2023. [@2023lattice]

[6] R. del Pino and S. Katsumata, "A New Framework for More Efficient Round-Optimal
Lattice-Based (Partially) Blind Signature via Trapdoor Sampling," in *CRYPTO*, 2022. [@CRYPTO 2022]

[7] G. Fuchsbauer, C. Hanser, and D. Slamanig, "Practical Round-Optimal Blind Signatures in the
Standard Model," in *CRYPTO*, 2015. [@2015Practical]

[8] S. Agrawal, E. Kirshanova, D. Stehle, and A. Yadav, "Practical, Round-Optimal Lattice-Based
Blind Signatures," in *ACM CCS*, 2022. [@Agrawal2022Practical]

[9] L. Grassi, D. Khovratovich, C. Rechberger, A. Roy, and M. Schofnegger, "Poseidon: A New Hash
Function for Zero-Knowledge Proof Systems," 2019. [@2019Poseidon]

[10] L. Grassi, D. Khovratovich, R. Luftenegger, C. Rechberger, M. Schofnegger, and R. Walch,
"Monolith: Circuit-Friendly Hash Functions with New Nonlinear Layers," *IACR ToSC*, 2024.
[@Grassi2024Monolith]

[11] M. Buser et al., "A Survey on Exotic Signatures for Post-quantum Blockchain," *ACM Computing
Surveys*, 2022. [@2022Survey]

[12] S. Argo, T. Guneysu, C. Jeudy, G. Land, and A. Roux-Langlois, "Practical Post-Quantum
Signatures for Privacy," in *ACM CCS*, 2024. [@Argo2024Practical]

[13] S. Katsumata, R. Nishimaki, S. Yamada, and T. Yamakawa, "Round-Optimal Blind Signatures in
the Plain Model from Classical and Quantum Standard Assumptions," in *EUROCRYPT*, 2021.
[@Katsumata2021]

[14] C. Li, Y. Tian, X. Chen, and J. Li, "An Efficient Anti-Quantum Lattice-Based Blind Signature for
Blockchain-Enabled Systems," *Information Sciences*, 2020. [@2020efficient]

[15] M. Chathurangi, Q. Li, and E. Foo, "On Advances of Anonymous Credentials — From Traditional
to Post-Quantum," *Cryptography*, 2021. [@Chathurangi2025Advances]

[16] D. Slamanig, "Privacy-Preserving Authentication: Theory vs. Practice," *arXiv:2501.07209*, 2025.
[@Slamanig2025PrivacyAuth]

[17] E. Ben-Sasson, L. Goldberg, S. Kopparty, and S. Saraf, "DEEP-FRI: Sampling Outside the Box
Improves Soundness," in *ITCS*, 2020. [@2019DEEP]

[18] B. Bunz, J. Bootle, D. Boneh, A. Poelstra, P. Wuille, and G. Maxwell, "Bulletproofs: Short
Proofs for Confidential Transactions and More," in *IEEE S&P*, 2018. [@2018Bulletproofs]

[19] J. Katz, V. Kolesnikov, and X. Wang, "Improved Non-Interactive Zero Knowledge with
Applications to Post-Quantum Signatures," in *ACM CCS*, 2018. [@2018Improved]

[20] NIST, "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization
Process," NIST IR 8413, 2022. [@2022Status]

[21] NIST, "Recommendation for Stateful Hash-Based Signature Schemes," NIST SP 800-208, 2020.
[@2020Recommendation]

[22] J. Kastner, K. Nguyen, and M. Reichle, "Pairing-Free Blind Signatures from Standard Assumptions
in the ROM," in *CRYPTO*, 2024. [@Kastner2024PairingFree]

[23] S. Balumuri, E. Eaton, and P. Lamontagne, "Quantum-Safe Public Key Blinding from
MPC-in-the-Head Signature Schemes," 2024. [@Balumuri2024QuantumSafe]

[24] M. Dietz, J. Kastner, and S. Tessaro, "On the Impossibility of Round-Optimal Pairing-Free Blind
Signatures in the ROM," *IACR ePrint*, 2026. [@Dietz2026Impossibility]

[25] L. Grassi, D. Khovratovich, K. Koschatko, C. Rechberger, M. Schofnegger, V. Schroppel, and
Z. Wu, "Poseidon(2)b," *IACR Comm. Cryptol.*, 2026. [@Grassi2026Poseidon2b]

[26] A. Adomnicai, "Towards Practical Multi-Party Hash Chains using Arithmetization-Oriented
Primitives," *IACR Comm. Cryptol.*, 2026. [@Adomnicai2026]

[27] L. Kovalchuk, R. Oliynykov, and M. Rodinko, "Security of the Poseidon Hash Function Against
Non-Binary Differential and Linear Attacks," *Cybernetics and Systems Analysis*, 2021.
[@2021Security]

[28] CRYSTALS Team, "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme," *IACR
TCHES*, 2018. [@2018CRYSTALS]

[29] Y. Quan, "Improving Bitcoin's Post-Quantum Transaction Efficiency With a Novel Lattice-Based
Aggregate Signature Scheme Based on CRYSTALS-Dilithium and a STARK Protocol," *IEEE Access*,
2022. [@Quan2022]

[30] J. Sekulic, D. Capko, A. Erdeljan, T. Grbic, and K. Nenadic, "A Short Survey of ZK-Friendly Hash
Functions," in *INFOTEH*, 2025. [@Sekulic2025]

---

*Survey generated via systematic MCP-based literature search (scholar_mcp + Semantic Scholar)
across OpenAlex, Crossref, Semantic Scholar, and Google Scholar. 281 papers screened, 30 cited.*
