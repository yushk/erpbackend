#!/bin/bash

# RSA私钥生成
openssl genrsa -out ./bin/certs/ca.key 2048
# pkcs#8私钥生成
# openssl pkcs8 -topk8 -inform PEM -in ./bin/certs/ca.key -outform PEM -nocrypt -out ./bin/certs/pkcs8.key
# pem公钥生成
openssl rsa -in ./bin/certs/ca.key -pubout -out ./bin/certs/ca.pem