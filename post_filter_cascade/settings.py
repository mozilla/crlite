from decouple import config


KINTO_SERVER_URL = config(
    'KINTO_SERVER_URL', default='https://settings-writer.stage.mozaws.net/v1/'
)
KINTO_AUTH_USER = config('KINTO_AUTH_USER', default='')
KINTO_AUTH_PASSWORD = config('KINTO_AUTH_PASSWORD', default='')
KINTO_BUCKET = config('KINTO_BUCKET', default='')
KINTO_COLLECTION = config('KINTO_COLLECTION', default='')
