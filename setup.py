import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

name = "heapcalc"

setuptools.setup(
    name=name,
    version="0.0.1",
    author="Eloy Perez",
    author_email="zer1t0ps@protonmail.com",
    description="Calculates heap chunk sizes of malloc and bins",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/Zer1t0/" + name,
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "heapcalc = heapcalc.__main__:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
)
