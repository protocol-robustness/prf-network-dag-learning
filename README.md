# PRF Network DAG Learning Example

A small, executable learning repo showing how PRF evidence nodes can be packaged
as a network-scoped, forkable DAG and checked independently by two local replicas.

This is a teaching example. It is not a PRF network protocol, canonical PRF
schema, consensus implementation, or production ratification service. “Replica”
here means a second local verifier given the same packet and a separately
configured trusted network root. It does not mean peers exchanged data or agreed
on the globally current graph.

## Run it

Requirements: Java 17+ and Clojure CLI.

```sh
clojure -M:run
clojure -M:test
```

The first run fetches the pinned PRF framework dependency. The CLI prints the
network root, graph root, node/head counts, and whether both local replicas
accept the same packet.

## What the example contains

`src/prf/network/dag/learning.clj` builds one immutable network context with a
membership snapshot and a simple ratification policy. It creates a shared claim
basis node, then three child attestations: two approvals and one preserved
rejection/dissent. The child nodes form a fork from the same basis. PRF's
attestation DAG builder gives those nodes canonical content identities and
PRF's node validator checks node hashes, parent references, duplicates and
cycles. The graph wrapper binds the node set to the network context and gets a
separate domain-separated root.

Each local replica checks:

- the network root against its locally trusted expected root;
- that every node carries the same network binding;
- the PRF execution-node DAG validation result;
- declared graph-edge structure and the wrapper's graph root.

The tests mutate the network identity, a node and a node's network binding to
show that mismatched packets fail closed.

## What the example does not establish

The membership list and threshold are illustrative inputs, not authenticated
appointments. The example attestations are structurally valid but not
cryptographically signed, and a `:rejected` claim is only a preserved dissent
record; it is not a policy evaluation. No code here counts votes into an
accepted decision or authorizes a consequential transition. A real consumer
must verify signer identity and eligibility, bind each attestation to the exact
basis and policy, evaluate ratification under its authority policy, and verify
the authorized result again when consuming it.

The example also does not provide peer discovery, transport, durable replicated
storage, fork choice, append authorization, equivocation handling, ordering,
finality, or a truthful global “latest” view. Content addressing proves that a
packet matches its contents; reachability proves graph connectivity within that
packet. Neither proves that the packet is complete or current.

## Checkpoint head observation (integration exercise)

`src/prf/network/dag/head_observation.clj` adds a deliberately small read-only
HTTP adapter for PRO-94. A source exposes `GET /head?nonce=...` and returns one
EDN `head-observation.v1` value. The client sends a fresh random nonce to each
source and passes both responses to PRF's `verify-observed-heads` API. This repo
owns HTTP framing only; PRF owns signature, network/key binding, freshness,
certified-history and conflict checks. The transport does not accept writes,
choose a fork or assert global latestness.

The API is provided by the PRO-93 PRF checkpoint implementation. Until that
implementation is available in the framework revision pinned by `deps.edn`,
the transport tests run with an injected verifier callback and demonstrate how
an authenticated conflict result is carried through. To exercise the actual
PRF verifier from a local PRF checkout, add that checkout's `src` directory to
the classpath when running this project, for example:

```sh
clojure -Sdeps '{:deps {protocol-robustness/framework {:local/root "/path/to/protocol-robustness-framework"}}}' -M:test
```

Before treating this as a runnable public integration, update the framework
dependency to a published, reviewed PRF revision that exposes
`resolver-sim.network.checkpoint/verify-observed-heads`. The local adapter does
not copy or approximate that verifier.

The host application supplies `start-source!` an observation provider that
signs the nonce and current checkpoint for each request. It separately
configures the verifier with pinned source IDs, public keys and independence
groups, plus a certified history reconstructed through PRF. The adapter
generates a distinct nonce per source, then passes both artifacts and nonce
bindings to `prf-verifier`. A matching result means only that the configured
sources freshly reported the same certified head.

## How to extend the exercise

1. Replace the illustrative membership map with a frozen, authenticated
   authority snapshot and test appointment/removal transitions.
2. Sign each attestation and independently verify keys against that snapshot.
3. Bind attestations to a canonical basis root covering workflow/claim identity,
   question, evidence and policy roots.
4. Add a signed ratification decision that names the exact basis and verifies it
   again at consumption.
5. Only then design a transport and replication protocol. Specify fork handling,
   append authority, replay protection and how peers establish currentness before
   calling this a network-native DAG.

The PRF APIs in use are pinned in [`deps.edn`](deps.edn), rather than copied into
this repository. The local `prf-learning-*` envelope is deliberately namespaced
to avoid implying that it is an established canonical PRF schema.
