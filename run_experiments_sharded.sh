#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUTF8=1
export PYTHONPATH=".:${PYTHONPATH:-}"
out="${1:-reproduced}"
python -B run_experiments.py --out "$out" --prepare
for depth in 1 2 4 8 16 32 64 128 256 512 1024 2048; do
  python -B run_experiments.py --out "$out" --benchmark-depth "$depth"
done
python -B run_experiments.py --out "$out" --finalize
