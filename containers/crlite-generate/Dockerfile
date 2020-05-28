ARG crlite_image=crlite:latest
FROM $crlite_image

COPY containers/crlite-generate/crlite-generate.sh /app/
CMD [ "/bin/bash", "-xc", "/app/crlite-generate.sh" ]
