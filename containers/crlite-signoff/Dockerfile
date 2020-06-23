ARG crlite_image=crlite:latest
FROM $crlite_image

RUN pip3 install --user moz_crlite_query

COPY containers/crlite-signoff/crlite-signoff.sh /app/
COPY containers/crlite-signoff/crlite-signoff-tool.py /app/

CMD [ "/bin/bash", "-xc", "/app/crlite-signoff.sh" ]
