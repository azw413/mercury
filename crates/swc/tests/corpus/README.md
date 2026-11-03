# Generated JavaScript corpus

These standalone, deterministic scripts exercise Mercury's semantic
HBC-to-SWC-to-HBC roundtrip. They include calculation and benchmark-inspired
kernels, built-in objects, language semantics, and generated source-size stress
families. The 74 files range from small focused programs to a 2,048-statement
workload and 65,536-entry string, BigInt, and property stress files.

Regenerate them from the workspace root:

```sh
python3 crates/swc/tests/generate_corpus.py
python3 crates/swc/tests/generate_corpus.py --check
```

The files contain original test programs generated for this project. They do not
copy third-party benchmark suites.
