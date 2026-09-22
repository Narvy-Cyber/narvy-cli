"""Compatibility shim for legacy `python setup.py` invocations.

All metadata lives in pyproject.toml. Prefer `python -m build`.
"""
from setuptools import setup

setup()
