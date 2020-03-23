from setuptools import setup

setup(
    name="moz_crlite_lib",
    version="0.2",
    description="Formats and tools used for CRLite",
    long_description=(
        "This project contains common functions and structures used "
        + "in the creation and querying of CRLite data, which compresses all "
        + "revocation information for the Web PKI into a compact data structure."
    ),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Programming Language :: Python :: 3",
    ],
    keywords="bloom filter cascade multi level mlbf crlite",
    packages=["moz_crlite_lib"],
    url="http://github.com/mozilla/crlite",
    author="J.C. Jones",
    author_email="jc@mozilla.com",
    license="Mozilla Public License 2.0 (MPL 2.0)",
    zip_safe=True,
)
