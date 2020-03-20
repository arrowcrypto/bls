# Boneh–Lynn–Shacham Implementation

This is a Boneh–Lynn–Shacham signature implementation based on cloudflare bn256 curve.

## Benchmark

Average latency of 1000 times of operations

* Key generation: 369 us
* Sign: 152 us
* Verification: 2501 us
* 999 times signatures aggregation: 1342 us, i.e. averagely 1.34 us
* 999 public key aggregation: 3656 us, i.e. averagely 3.66 us
