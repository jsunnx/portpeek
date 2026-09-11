# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="portpeek",
    version="0.1.0",
    description="Windows/Linux 端口占用速查：谁占了我的 3000/5173/8080？",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="jsunnx",
    license="MIT",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "portpeek=portpeek.__main__:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Topic :: System :: Networking",
    ],
)
