#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=.
python run_experiments.py --prepare
for depth in 1 2 4 8 16 32 64 128 256 512 1024 2048; do
  python run_experiments.py --benchmark-depth "$depth"
done
python run_experiments.py --finalize
