#!/usr/bin/env python

import os.path
from os import path

from setuptools import setup, find_packages

test_requirements = ["pytest>=3"]

__version__ = ""
this_directory = path.abspath(path.dirname(__file__))
parent_directory = os.path.abspath(os.path.join(this_directory, os.pardir))

with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

try:
    with open(os.path.join(this_directory, "VERSION")) as version_file:
        __version__ = version_file.read().strip()
except Exception:
    __version__ = os.environ.get("PYTHON_FPE_VERSION", "0.0.1-alpha")

setup(
    name="pyFPE",
    python_requires=">=3.5",
    version=__version__,
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    description="Python FPE- Does Format preserving Encryption of values",
    license="MIT license, Apache License",
    # include_package_data=True,
    keywords="python-fpe, pyfpe_ff3, vaultless, tokenization",
    install_requires=["pycryptodome==3.10.1"],
    packages=find_packages(include=['pyfpe_ff3','pyfpe_ff3.*']),
    # package_dir={"": "pyfpe_ff3"},
    test_suite="tests",
    # tests_require=test_requirements,
    url="https://github.com/PuspenduBanerjee/python-fpe",
    zip_safe=False,
    trusted_host=["pypi.org"],
    long_description=long_description,
    long_description_content_type="text/markdown",
)
