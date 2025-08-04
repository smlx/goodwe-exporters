FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
ARG BINARY=binary-build-arg-not-defined
ENV BINARY=${BINARY}
ENTRYPOINT ["sh", "-c"]
CMD ["exec /${BINARY}"]
COPY ${BINARY} /
