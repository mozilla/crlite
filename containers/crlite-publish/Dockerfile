ARG crlite_image=crlite:latest
FROM $crlite_image

COPY containers/crlite-publish/crlite-publish.sh /app/
CMD [ "/bin/bash", "-xc", "/app/crlite-publish.sh" ]
