FROM alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
ARG BINARY=binary-build-arg-not-defined
ENV BINARY=${BINARY}
ENTRYPOINT ["sh", "-c"]
CMD ["exec /${BINARY}"]
COPY ${BINARY} /
