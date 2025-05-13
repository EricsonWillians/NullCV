# 🕳️ NullCV

> Proof-of-Work, Not Promises  
> A decentralized work protocol for those who refuse to beg.

---

## 💣 The Problem

The modern job market is broken by design.  
It rewards conformity over capability, branding over output, and obedience over truth.

- **LinkedIn** reduces human potential to sanitized profiles and social signaling.
- **Upwork/Fiverr** trap freelancers in race-to-the-bottom gladiator pits, extracting value for platform owners.
- **Hiring** is a game of keywords, credentials, and algorithmic guesswork—not skill.

NullCV rejects all of it.

---

## ✊ The Premise

```

workValue = actualOutput, not(credentials + connections + conformity)

````

No resumes.  
No endorsements.  
No cultural posturing.  
Only the work.  
Only the proof.

---

## 🧱 What Is NullCV?

NullCV is an **anti-platform**.

It’s a **peer-to-peer proof-of-work identity protocol**, built for humans who create value and refuse to beg for permission.

At its core, NullCV is:

- A **cryptographic identity system** with no resumes or bios
- A **WorkGraph**: your actual contributions, timestamped and verifiable
- A **zero-fee talent network** built on open protocols
- A direct **attack on credentialism, gatekeeping, and algorithmic hiring**

---

## 🧠 How It Works

### 🔐 Identity

- Every user generates a **cryptographic keypair**
- That key is their identity — no email, no signup
- Optional pseudonyms may exist, but never replace the key

### 📁 WorkGraph

```ts
User {
  pubKey: string,
  work: [
    {
      projectCID: string,             // IPFS hash
      timestamp: string,              // blockchain or PGP timestamp
      attestations: string[]          // cryptographic signatures from peers
    }
  ],
  reputation: {
    [skill]: score                    // non-transferable, earned through verified work
  }
}
````

### 🔎 Verification

* Work is hashed and uploaded to IPFS
* Trusted peers **review and sign** your work
* Reputation accrues **only from reviewed, timestamped, real-world output**
* No one can fake it. No one can buy it.

### 💬 Matching

* Clients post specs, not jobs
* Specs match work histories — not resumes
* Agreements are signed cryptographically and locked into escrow
* Everything is open, audit-proof, and anti-exploit by design

---

## 💸 Economic Model

* **0% platform fee**
* No premium features. No bidding. No boost buttons.
* Smart contract escrow + direct value transfer = **no middlemen**
* Reputation cannot be sold, gamed, or transferred — ever

---

## ⚔️ Rage-Fueled Architecture

| Layer        | Tech                      |
| ------------ | ------------------------- |
| Identity     | Ethereum Keypair / PGP    |
| Storage      | IPFS                      |
| Escrow       | Ethereum Smart Contracts  |
| Comms        | ActivityPub / Matrix      |
| Reputation   | zk-SNARKs / Signed Proofs |
| Coordination | Git-based WorkGraphs      |

> Designed to survive deplatforming, VC capture, and bullshit.

---

## 🚀 Getting Started

```bash
# Install the NullCV CLI
curl -sSL https://nullcv.org/install.sh | bash

# Generate your key
nullcv keygen

# Submit work
nullcv submit ./my-project --tag "infra/docker" --private

# Attest to others' work
nullcv verify <pubKey> <projectCID>

# View your WorkGraph
nullcv graph
```

---

## 🔍 Why This Exists

Because some of us don’t want to be influencers.
Because some of us build instead of brand.
Because we’re tired of shouting into the algorithmic void hoping a recruiter gives a damn.

Because we believe:

> 🧱 **Proof-of-work is more sacred than proof-of-network.**
> 🗡️ **The future of labor is cryptographic, sovereign, and honest.**

---

## 🕳️ Join the Rebellion

This is not a startup.
This is not a product.
This is a weapon.

* Clone the repo
* Fork the protocol
* Submit real work
* Attest to others
* Build a new world where labor is respected without permission

> 🩸 No resumes. No gatekeepers. No begging.
> Just proof.

**→ [https://nullcv.org](https://nullcv.org)**

---

## 🧷 License

[Anti-Exploitation License v1.0](./LICENSE) — Fork, fight, and keep it free.
