# creation de channel par rapport au CLI
Executer le script ``fabricConfigurationv2.bash`` et suivre les instruction

**Limitation**:
Dans cette version:
- **ne supporte pas encors le vHSM**
- L'integration du chaincode n'est pas encors pris en compte(query, gateway, ...)


**REMARQUE**:
- Adapter les path selon les votre
- Il est preferable de lancer le script dans un dossier isoler
- Lors de la creation de des dossier specifique au tout debut, il esy preferable de mettre les path par defaut au risque de complication sinon
- Chaque orgnaisation devrait avoir au moin un admin specifique(CLI)

```bash
# creation du canal

docker exec cli.org1.example.com \
  peer channel create \
  -o orderer.example.com:7050 \
  -c canaltest \
  -f /var/hyperledger/orderer/channel-artifacts/canaltest.tx \
  --outputBlock /var/hyperledger/orderer/channel-artifacts/canaltest.block \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

faire rejoindre les peers:

```bash
# peer0 (ciblé par défaut)
docker exec cli.org1.example.com \
  peer channel join -b /var/hyperledger/orderer/channel-artifacts/canaltest.block
```

```bash
# peer1 (surcharge l'adresse)
docker exec -e CORE_PEER_ADDRESS=peer1.org1.example.com:7051 cli.org1.example.com \
  peer channel join -b /var/hyperledger/orderer/channel-artifacts/canaltest.block
```

```bash
# peer 2 
docker exec -e CORE_PEER_ADDRESS=peer0.org2.exemple.com:7051 cli.org2.exemple.com \
  peer channel join -b /var/hyperledger/orderer/channel-artifacts/canaltest.block
```

### VERIFICATION:
```bash
#Verifie que le block du channel a bien ete creer
#peer0 par defaut
cmd : docker exec cli.org1.example.com ls -la /var/hyperledger/orderer/channel-artifacts/canaltest.block
```

```bash
# autre peer
cmd: docker exec -e CORE_PEER_ADDRESS=peer1.org1.example.com:7051 cli.org1.example.com peer channel list
```

verification de la taille du canal
```bash
cmd : docker exec cli.org1.example.com peer channel getinfo -c canaltest
```

