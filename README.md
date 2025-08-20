# Adaptor signatures

## Introduction

Adaptor signatures (also called signature adaptors) are auxiliary signature data that commit to a hidden value. When an adaptor is combined with a corresponding signature, it reveals the hidden value. Alternatively, when combined with the hidden value, the adaptor reveals the signature. Other people may create secondary adaptors that reuse the commitment even if they don’t know the hidden value. This makes adaptors a powerful tool for implementing locking in bitcoin contracts.

[See the source from Bitcoin Optech](https://bitcoinops.org/en/topics/adaptor-signatures/)
