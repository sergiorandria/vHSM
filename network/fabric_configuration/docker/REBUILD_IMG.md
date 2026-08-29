### 1. Rebuild the image
```bash
docker build -t thesis2-ccaas:1.0 -f ./chaincode/firstcanal/Dockerfile ./chaincode/firstcanal/
```

### 2. Restart the container
```bash
docker stop cc-peer0.misa.university.com
docker rm cc-peer0.misa.university.com
docker-compose up -d cc-peer0.misa.university.com
```

### 3. Verify
```bash
docker logs cc-peer0.misa.university.com --tail 10
```
