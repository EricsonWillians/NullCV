# 🕳️ NullCV

> Proof-of-Work, Not Promises  
> A decentralized work protocol for those who refuse to beg.

![NullCV](https://nullcv.org/banner.png)

## 🔥 The Problem

The job market is fundamentally broken:

- **LinkedIn** reduces humans to sanitized profiles and social theater
- **Upwork/Fiverr** trap talent in extractive race-to-the-bottom platforms
- **Resumes** reward credential collection, not capability
- **Hiring** has become algorithmic gatekeeping, favoring keywords over competence

We didn't come to play their game better. **We came to end it.**

## 💡 The Solution: NullCV

NullCV is a **decentralized proof-of-work identity protocol** that eliminates credentials, middlemen, and algorithmic bias.

```
workValue = actualOutput, not(credentials + connections + conformity)
```

**Core principles:**
- Your work speaks for itself
- Verification over certification
- Zero platform fees
- Cryptographic identity, not social performance
- Direct value exchange without extractive middlemen

## 🧠 How It Works

### 🔐 Identity
- Every user generates a **cryptographic keypair** - that's your identity
- No email, no signup, no social validation required
- Optional pseudonyms for human readability

### 📊 WorkGraph

```ts
User {
  pubKey: string,
  work: [
    {
      projectCID: string,             // IPFS hash of your work
      timestamp: string,              // blockchain or PGP timestamp
      attestations: string[]          // cryptographic signatures from peers
    }
  ],
  reputation: {
    [skill]: score                    // non-transferable, earned through verified work
  }
}
```

### ✅ Verification
- Work is hashed and uploaded to IPFS
- Trusted peers review and cryptographically sign your work
- Reputation accrues only from verified, timestamped, real-world output
- Zero-knowledge proofs enable verification without revealing sensitive details

### 🤝 Matching
- Clients post specifications, not job listings
- Specs match work histories, not resumes
- Direct client-worker relationships without platform interference
- Agreements are cryptographically signed and locked in escrow

## 🏗️ Architecture

| Layer        | Technology                 |
|--------------|----------------------------|
| Identity     | Ethereum Keypair / PGP     |
| Storage      | IPFS                       |
| Escrow       | Ethereum Smart Contracts   |
| Comms        | ActivityPub / Matrix       |
| Reputation   | zk-SNARKs / Signed Proofs  |
| Coordination | Git-based WorkGraphs       |

## 🛡️ Safeguards

NullCV implements critical protections against dystopic outcomes:

- **Right to Reinvention**: Reputation decay and clean slate protocols
- **Human-in-the-Loop**: No fully automated reputation penalties
- **Anti-Plutocratic Design**: Contribution value over economic power
- **Career Mobility**: Skill bridges and cross-domain transitions
- **Multiple Entry Paths**: Skill challenges and mentorship programs

See our [Protective Guidelines](./docs/PROTECTIVE_GUIDELINES.md) for our comprehensive safeguards.

## 🚀 Getting Started

```bash
# Install the NullCV CLI
curl -sSL https://nullcv.org/install.sh | bash

# Generate your cryptographic identity
nullcv keygen

# Submit work for verification
nullcv submit ./my-project --tag "infra/docker" --private

# Verify others' work
nullcv verify <pubKey> <projectCID>

# View your WorkGraph
nullcv graph
```

## 🤔 Why NullCV Exists

Because we believe:

> **Proof-of-work is more sacred than proof-of-network.**
>
> **The future of labor is cryptographic, sovereign, and honest.**

We reject a world where your value is determined by:
- Who you know
- Where you went to school
- How well you perform social conformity
- How effectively you game recruitment algorithms

## 👥 Who Should Join

- **Builders** who are tired of credential games
- **Clients** who want real talent, not keyword matching
- **Knowledge workers** trapped in resume hell
- **Self-taught professionals** prejudiced by credentialism
- **Anyone** who believes capability trumps credentials

## 🧩 How to Contribute

NullCV is an open protocol, not a closed platform. Join us:

1. **Use it**: Generate your key, submit work, verify others
2. **Develop it**: Contribute to our [GitHub repo](https://github.com/nullcv)
3. **Spread it**: Tell others who are tired of begging for work
4. **Fork it**: Create specialized implementations for different domains

## 🌐 Community

- **Matrix**: [#nullcv:matrix.org](https://matrix.to/#/#nullcv:matrix.org)
- **Forum**: [forum.nullcv.org](https://forum.nullcv.org)
- **Git**: [github.com/nullcv](https://github.com/nullcv)
- **Docs**: [docs.nullcv.org](https://docs.nullcv.org)

## 🔮 Roadmap

- **Q2 2023**: Protocol specification and reference implementation
- **Q3 2023**: CLI tools and developer API
- **Q4 2023**: Web interface and initial network growth
- **Q1 2024**: Mobile clients and expanded verification tools
- **Q2 2024**: Cross-chain support and enhanced privacy features

## 🧷 License

[The Cryptographic Commons License (CCL)](./LICENSE) — Fork, fight, and keep it free.

---

> *"We refuse to beg for the right to create value. We simply create it, verify it, and connect directly with those who value it."*

**→ [https://nullcv.org](https://nullcv.org)**