# 1. Remove broken container and clean compose
docker rm -f cc-peer0.misa.university.com 2>/dev/null || true
rm docker-compose.yaml
./generate-network-2.sh        # regenerates compose only

# 2. Restart network
docker compose down
docker compose up -d

# 3. Rejoin orderer and peer to channel
osnadmin channel join --channelID canaltest \
  --config-block ./channel-artifacts/canaltest_genesis.block \
  -o orderer.university.com:7053 \
  --ca-file crypto-config/ordererOrganizations/university.com/orderers/orderer.university.com/tls/ca.crt \
  --client-cert crypto-config/ordererOrganizations/university.com/orderers/orderer.university.com/tls/server.crt \
  --client-key crypto-config/ordererOrganizations/university.com/orderers/orderer.university.com/tls/server.key

docker exec -it cli.misa.university.com peer channel join \
  -b /var/hyperledger/orderer/channel-artifacts/canaltest_genesis.block

# 4. Rerun chaincode script
bash chaincode-config-2.bash