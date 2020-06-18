ARG crlite_image=crlite:latest
FROM $crlite_image

COPY containers/crlite-signoff/crlite-signoff.sh /app/
CMD [ "/bin/bash", "-xc", "/app/crlite-signoff.sh" ]
