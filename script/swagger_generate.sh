#!/bin/bash
set -e -o pipefail

# Generates server & client code based on swagger spec. Uses existing model's structures.
# the spec references the model.json which is generated from code using generate-models.sh
# For server, spec must be flattened first, otherwise the embedded spec still contains
# references to external file and does not validate properly when services are started.

: ${WORKDIR:="./apiserver/"}
: ${QUIET:=""}
: ${SWAGGER:="swagger.yaml"}
: ${APP:="material"}
: ${TARGET:=""}
: ${PACKAGE:="v1"}

# export GOROOT="/usr/lib/go-1.12.5"

SERVER_COMMAND="pushd ${WORKDIR} && \
                swagger generate server ${QUIET}  -A ${APP} -t ./${TARGET} -f ./swagger/${SWAGGER} --model-package=${PACKAGE} && \
                cp ./cmd/material-server/main.go ./ && \
                popd"

CLEAN_COMMAND="pushd ${WORKDIR} && \
                rm -rf ./client && \
                rm -rf ./cmd && \
                rm -rf ./main.go && \
                rm -rf ./restapi/operations && \
                rm -rf ./restapi/doc.go && \
                rm -rf ./restapi/embedded_spec.go && \
                rm -rf ./restapi/server.go && \
                rm -rf ./v1 && \
                rm -rf ./swagger/models.json && \
               popd"

bash -c "${CLEAN_COMMAND}"
bash -c "${SERVER_COMMAND}"
