FROM alpine:3.22@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412
ARG BINARY=binary-build-arg-not-defined
ENV BINARY=${BINARY}
ENTRYPOINT ["sh", "-c"]
CMD ["exec /${BINARY}"]
COPY ${BINARY} /
