from kinto_http import Client

import settings
from ..certs_to_crlite import MLBF_FILENAME

client = Client(
    server_url=settings.KINTO_SERVER_URL,
    auth=(settings.KINTO_AUTH_USER, settings.KINTO_AUTH_PASSWORD),
    bucket=settings.KINTO_BUCKET,
    collection=settings.KINTO_COLLECTION,
)


client.create_record(data={
    'details': {'name': MLBF_FILENAME},
    'incremental': False
})
