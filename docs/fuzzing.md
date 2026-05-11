# Fuzzing KrakenWaf

KrakenWaf ships three `cargo-fuzz` targets that cover the most security-critical parsing paths.

## Prerequisites

```bash
cargo install cargo-fuzz
# cargo-fuzz requires a nightly compiler for the sanitiser flags:
rustup install nightly
```

## Fuzz targets

| Target | What it covers |
|---|---|
| `cmc_inspect` | Full CMC module pipeline — all 12 detectors + Java deserialise scoring |
| `url_decode` | Multi-pass URL-decode normalisation via the CMC inspection entry-point |
| `parse_rules` | Lenient YAML parser for `rules/cmc/config.yaml` |

## Running

```bash
# From the repository root — always use nightly for cargo-fuzz
cargo +nightly fuzz run cmc_inspect
cargo +nightly fuzz run url_decode
cargo +nightly fuzz run parse_rules

# Limit corpus to 1 MiB inputs and run for 10 minutes:
cargo +nightly fuzz run cmc_inspect -- -max_len=1048576 -max_total_time=600
```

## Corpus and crashes

libFuzzer writes generated inputs to `fuzz/corpus/<target>/` and crashes to `fuzz/artifacts/<target>/`. Commit interesting corpus files so subsequent runs start from a richer seed set.

## Reproducing a crash

```bash
cargo +nightly fuzz run cmc_inspect fuzz/artifacts/cmc_inspect/<crashing-file>
```

## CI integration

To run fuzz targets in CI for a short sanity check (not a full campaign):

```yaml
- name: Fuzz (short)
  run: |
    cargo +nightly fuzz run cmc_inspect -- -max_total_time=30
    cargo +nightly fuzz run url_decode  -- -max_total_time=30
    cargo +nightly fuzz run parse_rules -- -max_total_time=30
```
