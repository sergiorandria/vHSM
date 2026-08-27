FROM golang:1.26
WORKDIR /chaincode
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /chaincode/cc .
EXPOSE 9999
CMD ["/chaincode/cc"]
