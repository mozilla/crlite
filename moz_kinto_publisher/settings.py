from decouple import config

KINTO_RW_SERVER_URL = config(
    "KINTO_RW_SERVER_URL", default="https://settings-writer.stage.mozaws.net/v1/"
)
KINTO_RO_SERVER_URL = config(
    "KINTO_RO_SERVER_URL", default="https://settings-cdn.stage.mozaws.net/v1/"
)
KINTO_AUTH_USER = config("KINTO_AUTH_USER", default="")
KINTO_AUTH_PASSWORD = config("KINTO_AUTH_PASSWORD", default="")
KINTO_BUCKET = config("KINTO_BUCKET", default="security-state-staging")
KINTO_CRLITE_COLLECTION = config("KINTO_CRLITE_COLLECTION", default="cert-revocations")
KINTO_INTERMEDIATES_COLLECTION = config(
    "KINTO_INTERMEDIATES_COLLECTION", default="intermediates"
)
KINTO_CTLOGS_COLLECTION = config("KINTO_CTLOGS_COLLECTION", default="ct-logs")
