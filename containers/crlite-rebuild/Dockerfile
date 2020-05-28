ARG crlite_image=crlite:latest
FROM $crlite_image

COPY containers/crlite-rebuild/crlite-rebuild.sh /app/
CMD [ "/bin/bash", "-xc", "/app/crlite-rebuild.sh" ]
