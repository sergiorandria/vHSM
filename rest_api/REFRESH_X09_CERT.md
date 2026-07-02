```bash
# Copy the current peer TLS CA cert from the container
docker exec peer0.misa.university.com cat /etc/hyperledger/fabric/tls/ca.crt \
  | sudo tee /etc/vhsmd/crypto/peers/peer0.misa.university.com/tls/ca.crt

# Verify they now match
docker exec peer0.misa.university.com cat /etc/hyperledger/fabric/tls/ca.crt \
  | diff - /etc/vhsmd/crypto/peers/peer0.misa.university.com/tls/ca.crt
```

also refresh the user cert and key since those may be stale too:
```bash
# Refresh user cert
docker exec cli.misa.university.com \
  cat /etc/hyperledger/fabric/admin-msp/signcerts/Admin@misa.university.com-cert.pem \
  | sudo tee /etc/vhsmd/crypto/users/Admin@misa.university.com/msp/signcerts/Admin@misa.university.com-cert.pem

# Refresh user key (find the keystore file name first)
docker exec cli.misa.university.com ls /etc/hyperledger/fabric/admin-msp/keystore/
```

Then restart:
```bash
sudo systemctl restart vhsm.service
sudo journalctl -u vhsm.service -f
```