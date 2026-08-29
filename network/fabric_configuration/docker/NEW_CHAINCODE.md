# ── 1. Rebuild l'image CCaaS avec le nouveau code source ──────────────────
docker build -t thesis-ccaas:1.1 -f chaincode/firstcanal/Dockerfile chaincode/firstcanal

# ── 2. Installer le nouveau package sur CHAQUE peer ────────────────────────
# (le tar.gz thesis_1.1.tar.gz doit déjà exister — même méthode que chaincode-config.sh,
# label = thesis_1.1, connection.json inchangé)

docker cp chaincode/firstcanal/peer0.misa.university.com/thesis_1.1.tar.gz \
  cli.misa.university.com:/var/hyperledger/orderer/channel-artifacts/thesis_1.1_peer0.tar.gz
docker exec -e CORE_PEER_ADDRESS=peer0.misa.university.com:7051 cli.misa.university.com \
  peer lifecycle chaincode install /var/hyperledger/orderer/channel-artifacts/thesis_1.1_peer0.tar.gz

docker cp chaincode/firstcanal/peer1.misa.university.com/thesis_1.1.tar.gz \
  cli.misa.university.com:/var/hyperledger/orderer/channel-artifacts/thesis_1.1_peer1.tar.gz
docker exec -e CORE_PEER_ADDRESS=peer1.misa.university.com:7051 cli.misa.university.com \
  peer lifecycle chaincode install /var/hyperledger/orderer/channel-artifacts/thesis_1.1_peer1.tar.gz

# ── 3. Récupérer le Package ID (identique sur les deux peers si même tar.gz) ──
docker exec -e CORE_PEER_ADDRESS=peer0.misa.university.com:7051 cli.misa.university.com \
  peer lifecycle chaincode queryinstalled

# ── 4. Basculer les conteneurs CCaaS sur la nouvelle image + le nouveau Package ID ──
# (éditez docker-compose.yaml : image -> thesis-ccaas:1.1, CORE_CHAINCODE_ID_NAME -> le nouveau package-id, pour cc-peer0.* et cc-peer1.*)
docker compose up -d --force-recreate cc-peer0.misa.university.com cc-peer1.misa.university.com

# ── 5. Approuver la nouvelle définition pour votre org (séquence +1) ──────
docker exec -e CORE_PEER_LOCALMSPID=misaMSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/admin-msp cli.misa.university.com \
  peer lifecycle chaincode approveformyorg \
  -o orderer.university.com:7050 --channelID firstcanal --name thesis \
  --version 1.1 --package-id thesis_1.1:<HASH_ÉTAPE_3> --sequence 2 --init-required \
  --tls --cafile /etc/hyperledger/orderer/tls/ca.crt

# ── 6. Vérifier la readiness ────────────────────────────────────────────
docker exec cli.misa.university.com peer lifecycle chaincode checkcommitreadiness \
  -o orderer.university.com:7050 --channelID firstcanal --name thesis \
  --version 1.1 --sequence 2 --init-required --tls --cafile /etc/hyperledger/orderer/tls/ca.crt --output json

# ── 7. Commit ────────────────────────────────────────────────────────────
docker exec cli.misa.university.com peer lifecycle chaincode commit \
  -o orderer.university.com:7050 --channelID firstcanal --name thesis \
  --version 1.1 --sequence 2 --init-required \
  --peerAddresses peer0.misa.university.com:7051 \
  --tlsRootCertFiles /etc/hyperledger/fabric/tls/ca.crt \
  --tls --cafile /etc/hyperledger/orderer/tls/ca.crt
