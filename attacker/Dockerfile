# A lightweight attacker container for the isolated attacker network.
#
# Kali Linux is the "official" attacker image, but it is huge (~2 GB+) and
# amd64-only, so it is very slow under Rosetta emulation on the M1. This slim
# image carries only the tools we actually use in the five scenarios:
# nmap, plus python with pymodbus and requests.
#
# Build & get a shell:
#   docker build -t honeynet-attacker .
#   docker run --rm -it --network attacker-net honeynet-attacker
# then run the scripts, e.g.:  python scripts/run_all.py

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pymodbus==3.6.9 requests==2.32.3

COPY scripts/ /attacker/scripts/
WORKDIR /attacker

CMD ["bash"]
