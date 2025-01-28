FROM alpine
ARG BINARY_FILE=""
WORKDIR /app
RUN apk update && apk add --no-cache ca-certificates
COPY ${BINARY_FILE} regcred-ecr
CMD [ "./regcred-ecr" ]

