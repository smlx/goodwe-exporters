FROM alpine:3.21@sha256:21dc6063fd678b478f57c0e13f47560d0ea4eeba26dfc947b2a4f81f686b9f45
ARG BINARY=binary-build-arg-not-defined
ENV BINARY=${BINARY}
ENTRYPOINT ["sh", "-c"]
CMD ["exec /${BINARY}"]
COPY ${BINARY} /
