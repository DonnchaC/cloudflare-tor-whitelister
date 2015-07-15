# -*- coding: utf-8 -*-

"""setup.py: setuptools control."""

import io
import os

from setuptools import setup


def read(*names, **kwargs):
    return io.open(
        os.path.join(os.path.dirname(__file__), *names),
        encoding=kwargs.get("encoding", "utf8")
    ).read()


setup(
    name="cloudflare-tor-whitelister",
    packages=["cfwhitelist"],
    entry_points={
        "console_scripts": [
            "cloudflare-whitelist = cfwhitelist.whitelist:main",
        ]},
    description="Cloudflare Whitelister allows site owners to explicitly "
    "allow Tor users access there site without being impeded by CAPTCHAs ",
    long_description=read("README.rst"),
    version="0.1.0",
    author="Donncha O'Cearbhail",
    author_email="donncha@donncha.is",
    url="https://github.com/DonnchaC/cloudflare-tor-whitelister",
    license="GPLv3",
    keywords="tor, cloudflare, firewall",
    install_requires=['requests'],
)
