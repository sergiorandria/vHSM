FROM golang:1.26-bookworm AS builder
WORKDIR /chaincode
COPY src/ .
RUN go mod tidy && go build -o /chaincode-bin .

FROM debian:bookworm-slim
WORKDIR /chaincode
COPY --from=builder /chaincode-bin /chaincode/chaincode-bin
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
EXPOSE 9999
ENTRYPOINT ["/chaincode/chaincode-bin"]
