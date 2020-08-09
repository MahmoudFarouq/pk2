#!/bin/bash
set -ex

if ! command -v cargo &> /dev/null
then
    curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain stable -y
    export PATH="$HOME/.cargo/bin:$PATH"
fi

pip install -U setuptools wheel setuptools-rust
python setup.py bdist_wheel

for whl in dist/*.whl; do
    auditwheel repair "$whl" -w dist/
done
