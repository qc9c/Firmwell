#!/bin/bash
git clone https://github.com/fkie-cad/fact_extractor.git /tmp/fact_extractor && \
cp ./fact_extractor.diff /tmp/fact_extractor/fact_extractor.diff && \
cd /tmp/fact_extractor && \
git checkout 3eec1ebf7a1a2cc90ca9da0862de2f777482d11c && \
git apply ./fact_extractor.diff && \
DOCKER_BUILDKIT=1 docker build -t fkiecad/fact_extractor . && \
rm -rf /tmp/fact_extractor

docker save fkiecad/fact_extractor:latest -o fact_extractor.tar