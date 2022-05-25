from distutils.core import setup

setup(
    name="crlite",
    version="1.0.13",
    packages=["moz_kinto_publisher", "workflow"],
    install_requires=[
        "cryptography>=2.2",
        "glog>=0.3",
        "google-api-core",
        "google-cloud-core",
        "google-cloud-storage",
        "kinto-http>=10.9",
        "python-decouple>=3.1",
        "requests[socks]>=2.10.0",
    ],
)
