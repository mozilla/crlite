from setuptools import setup

setup(
    name="create_filter_cascade",
    version="0.1",
    description="Construct multi-level bloom filters for CRLite",
    long_description="This project changes raw serial number files from the 'crlite' "
    + "project into a multi-level bloom filter.",
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
    install_requires=["filtercascade", "psutil", "statsd"],
    include_package_data=True,
    zip_safe=False,
)
