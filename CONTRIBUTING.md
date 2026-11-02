# Contributing

Contributions are welcome, especially:

- new deterministic, read-only probe adapters;
- provenance-preserving source collectors;
- independently annotated applicability benchmarks;
- tests for conditions, ambiguity and omitted prerequisites;
- improvements to verifier robustness and supply-chain integrity;
- clearer documentation and reproducible research cases.

## Before a pull request

1. Open a discussion or issue describing the proposal and source-grounded behavior.
2. Add unit tests; no public internet or paid API calls are required in CI.
3. Run `python -m pytest -q`.
4. Never add private customer data, credentials, exploit payloads or unpublished vulnerability details.
5. Describe what the implementation supports **now** versus future work.

## Development ethics

Do not label fixtures `VERIFIED`. Do not weaken the verification gate to improve demo pass rates. Prefer `NEEDS_REVIEW` or `INCONCLUSIVE` to an ungrounded conclusion.
