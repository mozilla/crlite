ARG crlite_image=crlite:latest
FROM $crlite_image

COPY containers/crlite-fetch/crlite-fetch.sh /app/
CMD [ "/bin/bash", "-xc", "/app/crlite-fetch.sh" ]

ENV runForever true
ENV logExpiredEntries false
ENV logList https://ct.googleapis.com/icarus

EXPOSE 8080/tcp
