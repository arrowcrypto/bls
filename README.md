# Boneh–Lynn–Shacham Implementation

This is a Boneh–Lynn–Shacham signature implementation based on cloudflare bn256 curve.

## Benchmark

### Setup

* CPU
  * 2.3 GHz 8-Core Intel Core i9
  * L2 Cache (per Core): 256 KB
  * L3 Cache: 16 MB
  * Hyper-Threading enabled
* Memory: 32 GB 2400 MHz DDR4
* OS: macOS 10.15.3 (19D76)

### Performance
Average latency of 1000 times of operations

* Key generation: 369 us
* Sign: 152 us
* Verification: 2501 us
* 999 times signatures aggregation: 1342 us, i.e. averagely 1.34 us
* 999 public key aggregation: 3656 us, i.e. averagely 3.66 us
