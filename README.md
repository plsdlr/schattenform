# schattenform

## 1. What is this?

A prototype of a **ZK-proven digital object** — a single asset that passes between participants, where every ownership transfer and state update is cryptographically provable.

Built on [pod2](https://github.com/0xPARC/pod2) (0xPARC), a Rust library for building zero-knowledge proofs over structured data (PODs — Provable Object Data). The server is Axum. The frontend is plain HTML/JS with a brutalist black-and-white UI and an animated object signature that reflects the object's current state.

**The concept:** one object exists at a time. It carries a small set of integer values and an authorized writer. The current holder can update the values, designate a new holder, and produce a ZK proof that the transition was valid — without revealing their secret key to the server or anyone else. Each step commits to the previous state via a hash chain.

Three wallet views (`/alice`, `/bob`, `/charlie`) show each participant's identity, whether they currently hold the object, and their submitted proof history. An admin view (`/`) handles genesis creation and raw write operations.

---

## 2. How to run

**Prerequisites:** Rust nightly (pinned automatically via `rust-toolchain.toml`).

```bash
git clone git@github.com:plsdlr/schattenform.git
cd schattenform
cargo run --bin server
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000).

**Modes:**

| Command | Prover | Proof time |
|---|---|---|
| `cargo run --bin server` | MockProver (default) | instant — no real ZK |
| `cargo run --bin server -- --real-proofs` | Plonky2 | 12–25 min on a desktop |

Mock mode is indistinguishable from real mode in the UI — it skips the actual proof generation but exercises the full state machine and dict operations.

**Basic flow:**

1. Admin (`/`) → Create genesis: set initial integer values and first writer
2. Open the first writer's wallet (e.g. `/alice`)
3. Edit values, select next holder, click **Sign & Prove**
4. The baton moves — open the next wallet to continue

---

## 3. Specific characteristics of the schema

Every object state is a [Signed Dictionary](https://github.com/0xPARC/pod2) — a Sparse Merkle Tree of key-value pairs signed with a Schnorr key. The schema has two layers:

**System fields** (managed automatically, not editable in the UI):

| Field | Type | Role |
|---|---|---|
| `version` | `i64` | Monotonically incrementing counter. Proven via a `sum_of` constraint: `new_version = old_version + 1`. |
| `prev_hash` | `Dictionary` | Commitment to the previous state dict. Chains steps together into an immutable history without storing the full chain. |
| `writer_pk` | `PublicKey` | Schnorr public key of the currently authorized writer. A `public_key_of` constraint proves the writer holds the corresponding secret key without revealing it. |

**User fields** — arbitrary integer key-value pairs defined at genesis time (e.g. `val_a`, `val_b`, `val_c`). Any subset can be updated in a single write step; unchanged fields are preserved via SMT membership proofs.

**Each write step proves:**
1. The previous state was signed by the key named in `writer_pk` (`dict_signed_by`)
2. The writer possesses the secret key for that public key (`public_key_of`)
3. `writer_pk` was removed and replaced with the new holder's key (`dict_delete` + `dict_insert`)
4. Each updated user field was changed correctly (`dict_update` per field)
5. `version` incremented by exactly 1 (`sum_of`)
6. `prev_hash` was set to the hash of the previous state dict (`dict_update`)

**Proof cost** scales with the number of fields updated in a single step, not with the total number of fields, because the SMT depth is fixed at 256 levels regardless of dict size.
