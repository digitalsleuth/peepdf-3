from setuptools import setup

setup(
    name="peepdf-3",
    version="3.0.0",
    author="Jose Miguel Esparza, Corey Forman",
    license="GNU GPLv3",
    url="https://github.com/digitalsleuth/peepdf-3",
    description=("The original peepdf, ported to Python 3, and packaged in a setup"),
    install_requires=[
        "requests",
        "pypdf",
        "jsbeautifier",
        "colorama",
        "Pillow",
        "pythonaes",
        "lxml",
    ],
    entry_points={
        "console_scripts": [
            "peepdf = peepdf.peepdf:main",
        ],
    },
    packages=[
        "peepdf",
    ],
    package_data={"": ["README.md, COPYING"]},
)
