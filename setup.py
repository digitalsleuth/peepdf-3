from setuptools import setup

setup(
    name="peepdf-3",
    version="2.3.0-rc1",
    author="Jose Miguel Esparza, Corey Forman",
    license="GNU GPLv3",
    url="https://github.com/digitalsleuth/peepdf-3",
    description=("The original peepdf, ported to Python 3, and packaged in a setup"),
    install_requires=[
        "requests",
        "jsbeautifier",
        "colorama",
        "Pillow",
        "pylibemu",
        "pythonaes",
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
    package_data={"": ["README.md, COPYING"]},
)
