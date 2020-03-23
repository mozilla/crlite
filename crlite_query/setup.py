from setuptools import setup

setup(
    name="crlite_query",
    version="0.1",
    description="Query CRLite for a certificate, or certificate information",
    long_description="Use this tool to download and maintain CRLite information from "
    + "Mozilla's Remote Settings infrastructure, and query it.",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Programming Language :: Python :: 3",
    ],
    keywords="bloom filter cascade multi level mlbf crlite",
    url="http://github.com/mozilla/crlite",
    author="J.C. Jones",
    author_email="jc@mozilla.com",
    license="Mozilla Public License 2.0 (MPL 2.0)",
    include_package_data=True,
    zip_safe=False,
)
