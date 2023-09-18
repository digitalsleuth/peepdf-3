from setuptools import setup

setup(
    name="peepdf",
    version="1.0.9",
    author="Jose Miguel Esparza, Corey Forman",
    license="GNU GPLv3",
    url="https://github.com/digitalsleuth/peepdf-3",
    description= ("The original peepdf, ported to Python 3, and packaged in a setup"),
    install_requires=[
        "jsbeautifier",
        "colorama",
        "Pillow",
        "pythonaes",
        "pylibemu",
        "lxml",
    ],
    entry_points={
        "console_scripts": [
            "peepdf = peepdf.main:main",
        ],
    },
    packages=[
        "peepdf",
    ],
    package_data={'': ['README.md, COPYING']}
)
