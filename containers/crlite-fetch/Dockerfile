ARG crlite_image=crlite:latest
FROM $crlite_image

CMD [ "/bin/bash", "-xc", "/app/scripts/crlite-fetch.sh" ]

ENV runForever true
ENV logExpiredEntries false
ENV logList https://ct.googleapis.com/icarus

EXPOSE 8080/tcp
