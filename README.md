# PrivateDataVault

The durable half of the private-data pipeline: storage for documents and the values redacted out of them.

It sits alongside `PrivateDataShield` and `PrivateDataGateway`, which detect and
marshal private values inside the platform. Those two see the values; this one
keeps them. The platform processes and redacts; the PrivateDataVault keeps. Nothing private is retained
by the platform, and in the self-hosted deployment the platform holds no key to
retrieve it either.

## Two deployments, one codebase

| Deployment | Key held by | Can the platform read the data? |
| --- | --- | --- |
| Self-hosted — library or installed application | You | No |
| Managed — run by mAIvn, multi-tenant | mAIvn | Yes, and every decryption is logged |

The security property is the same code in both. Only key custody differs, and
that is the whole of the difference in what can be promised.

## Why this is open source

A vault whose safety depends on nobody reading it is not safe. The security has
to survive an attacker holding the source, which means it lives in the
cryptography and in key custody rather than in obscurity. Read it, audit it,
verify it does what is claimed here.

Compiled and signed all the same — not to hide the code, but so the binary on
your machine is hard to tamper with and does not depend on your language
runtime.

## Why Rust

The material this handles has to be destroyed on a deadline. A garbage-collected
language cannot promise that: it may have copied the value somewhere unreachable
and it decides for itself when to clean up. Rust frees deterministically and
lets the bytes actually be zeroed.

Some things remain outside any language's control -- the kernel can page memory
to disk, a crash can dump the heap. Those are handled by running each unit of
work in a short-lived process and by refusing to run on nodes that permit swap,
core dumps or checkpointing.

## Status

Work packages 1 and 2 are implemented: `private-data-vault-core` provides
memory-hard key derivation, zeroizing key ownership, authenticated value maps,
chunked document sealing, hard purge, and a ciphertext-only local storage
backend. `private-data-vault-py` provides the narrow abi3 Python 3.10+ local
vault interface. Wire protocol, application front doors, and managed storage
remain later work packages and are tracked in the maivn platform's
planning; releases of this crate note their scope in CHANGELOG.md.
