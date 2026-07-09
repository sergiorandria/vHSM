#!/usr/bin/env python3
"""
parse_configtx_orgs.py

Lit un configtx.yaml Hyperledger Fabric et extrait, pour chaque organisation
*peer* (donc en excluant l'OrdererOrg), son nom et son domaine, en se basant
uniquement sur les clefs "Name:" et "MSPDir:" du bloc "Organizations:".

Ne dépend d'aucune librairie YAML externe (PyYAML n'est pas toujours
installé) : on fait un parsing ligne à ligne, tolérant aux variations
d'indentation, ce qui permet de supporter N organisations sans modification.

Sortie : une ligne par organisation peer, au format "nom|domaine"
Exemple :
    misa|misa.university.com
    org2|org2.university.com
"""
import re
import sys


def extract_peer_orgs(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    orgs = []
    in_orgs_block = False
    current = None

    def flush(entry):
        if entry and entry.get("name") and entry.get("mspdir"):
            orgs.append(entry)

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if not in_orgs_block:
            # Repère le début du bloc top-level "Organizations:"
            if re.match(r"^Organizations\s*:\s*$", line):
                in_orgs_block = True
            continue

        # Une ligne non indentée et qui n'est pas un item de liste ("- ...")
        # marque la fin du bloc Organizations (ex: "Capabilities:")
        if line and not line[0].isspace() and not stripped.startswith("-"):
            flush(current)
            current = None
            break

        # Nouvelle entrée d'organisation : "    - &nomAncre"
        m = re.match(r"^\s*-\s*&(\S+)", line)
        if m:
            flush(current)
            current = {"anchor": m.group(1)}
            continue

        if current is not None:
            if "name" not in current:
                m = re.match(r"^Name\s*:\s*(\S+)", stripped)
                if m:
                    current["name"] = m.group(1)
                    continue
            if "mspdir" not in current:
                m = re.match(r"^MSPDir\s*:\s*(\S+)", stripped)
                if m:
                    current["mspdir"] = m.group(1)
                    continue

    flush(current)

    result = []
    for o in orgs:
        name = o["name"]
        mspdir = o["mspdir"]

        # On exclut l'organisation de l'orderer : ni pertinente pour le RBAC
        # applicatif (professeurs/etudiants/admin), ni un "peer" LDAP.
        if name == "OrdererOrg" or "ordererOrganizations" in mspdir:
            continue

        m = re.search(r"peerOrganizations/([^/]+)/", mspdir)
        if not m:
            continue
        domain = m.group(1)
        result.append((name, domain))

    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: parse_configtx_orgs.py <configtx.yaml>", file=sys.stderr)
        sys.exit(1)

    for name, domain in extract_peer_orgs(sys.argv[1]):
        print(f"{name}|{domain}")