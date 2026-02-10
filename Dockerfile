FROM devopsfaith/krakend:2.5

ARG CONFIG=hanzo

COPY configs/${CONFIG}/krakend.json /etc/krakend/krakend.json

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/__health || exit 1
