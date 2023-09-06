from setuptools import setup

setup(
    name="peepdf",
    version="1.0.4",
    author="Jose Miguel Esparza, Corey Forman",
    license="GNU GPLv3",
    url="http://eternal-todo.com",
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
)
