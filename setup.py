from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name='pk2',
    version="0.0.1",
    rust_extensions=[RustExtension('pk2', 'Cargo.toml',  binding=Binding.PyO3)],
    test_suite="tests",
    zip_safe=False
)