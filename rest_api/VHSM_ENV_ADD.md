Add these env variables to /etc/vhsm/vhsm.env

## Fabric
CRYPTO_PATH=/etc/vhsmd/crypto
MSP_ID=misaMSP
CHANNEL_NAME=firstcanal
CHAINCODE_NAME=thesis2
CERT_PATH=/etc/vhsmd/crypto/users/Admin@misa.university.com/msp/signcerts/Admin@misa.university.com-cert.pem
KEY_PATH=/etc/vhsmd/crypto/users/Admin@misa.university.com/msp/keystore
TLS_CERT_PATH=/etc/vhsmd/crypto/peers/peer0.misa.university.com/tls/ca.crt
PEER_ENDPOINT=127.0.0.1:7051
GATEWAY_PEER_NAME=peer0.misa.university.com