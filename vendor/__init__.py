"""Installed as `technocore_mcp.vendor` so the vendored client ships with the wheel.

This file exists only to make the directory a package, which is what lets
setuptools carry `e2e.py` and `UPSTREAM.txt` into the distribution. Nothing
imports from here: the vendored client is loaded by path, after its digest is
checked, through `technocore_mcp.vendorguard`.
"""
