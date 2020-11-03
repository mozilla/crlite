from distutils.core import setup

setup(
    name="crlite",
    version="1.0.0",
    packages=["create_filter_cascade", "moz_kinto_publisher", "workflow"],
    install_requires=[
        "bsdiff4>=1.1",
        "cryptography>=2.2",
        "Deprecated>=1.2",
        "filtercascade>=0.3.1",
        "glog>=0.3",
        "google-api-core",
        "google-cloud-core",
        "google-cloud-storage",
        "kinto-http>=9.1",
        "moz_crlite_lib>=0.2",
        "moz_crlite_query>=0.4.0",
        "progressbar2>=3.40",
        "psutil>=5",
        "pyOpenSSL>=17.5",
        "python-decouple>=3.1",
        "requests[socks]>=2.10.0",
        "statsd>=3.3",
    ],
)
