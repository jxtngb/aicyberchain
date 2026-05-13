import json
import time
import os
from web3 import Web3
from solcx import compile_standard, install_solc

# --------------------------------------------------
# SOLIDITY CONTRACT (EMBEDDED)
# --------------------------------------------------

install_solc("0.8.0")

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {
            "ThreatLog.sol": {
                "content": """
                pragma solidity ^0.8.0;

                contract ThreatLog {

                    struct Threat {
                        uint id;
                        string source_ip;
                        string destination_ip;
                        uint protocol;
                        uint packet_size;
                        string attack_type;
                        bool detected;
                        uint timestamp;
                    }

                    Threat[] public threats;

                    function addThreat(
                        uint id,
                        string memory source_ip,
                        string memory destination_ip,
                        uint protocol,
                        uint packet_size,
                        string memory attack_type,
                        bool detected,
                        uint timestamp
                    ) public {
                        threats.push(
                            Threat(
                                id,
                                source_ip,
                                destination_ip,
                                protocol,
                                packet_size,
                                attack_type,
                                detected,
                                timestamp
                            )
                        );
                    }

                    function getThreat(uint id) public view returns (
                        string memory,
                        string memory,
                        uint,
                        uint,
                        string memory,
                        bool,
                        uint
                    ) {
                        for (uint i = 0; i < threats.length; i++) {
                            if (threats[i].id == id) {
                                Threat memory t = threats[i];
                                return (
                                    t.source_ip,
                                    t.destination_ip,
                                    t.protocol,
                                    t.packet_size,
                                    t.attack_type,
                                    t.detected,
                                    t.timestamp
                                );
                            }
                        }
                        return ("NF","NF",0,0,"NF",false,0);
                    }

                    function getThreatCount() public view returns (uint) {
                        return threats.length;
                    }
                }
                """
            }
        },
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["metadata", "evm.bytecode"]
                }
            }
        }
    },
    solc_version="0.8.0"
)

# --------------------------------------------------
# BLOCKCHAIN CONNECTION
# --------------------------------------------------

GANACHE_URL = "http://127.0.0.1:7545"

def get_web3():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        raise Exception("Ganache not running")
    w3.eth.default_account = w3.eth.accounts[0]
    return w3

# --------------------------------------------------
# DEPLOY CONTRACT
# --------------------------------------------------

def create_contract():
    w3 = get_web3()

    bytecode = compiled_sol["contracts"]["ThreatLog.sol"]["ThreatLog"]["evm"]["bytecode"]["object"]
    abi = json.loads(
        compiled_sol["contracts"]["ThreatLog.sol"]["ThreatLog"]["metadata"]
    )["output"]["abi"]

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    tx_hash = contract.constructor().transact({
        "from": w3.eth.accounts[0],   # ✅ REQUIRED
        "gas": 3000000
    })

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    with open("contract_address.txt", "w") as f:
        f.write(receipt.contractAddress)

    print("✅ Contract deployed at:", receipt.contractAddress)


# --------------------------------------------------
# LOAD CONTRACT
# --------------------------------------------------

# def get_contract():
#     with open("contract_address.txt", "r") as f:
#         address = f.read().strip()

#     w3 = get_web3()

#     abi = json.loads(
#         compiled_sol["contracts"]["ThreatLog.sol"]["ThreatLog"]["metadata"]
#     )["output"]["abi"]

#     return w3.eth.contract(address=address, abi=abi)

def get_contract():
    # Get the folder where blockchain.py resides
    base_dir = os.path.dirname(os.path.abspath(__file__))
    contract_file = os.path.join(base_dir, "contract_address.txt")

    with open(contract_file, "r") as f:
        address = f.read().strip()

    w3 = get_web3()

    abi = json.loads(
        compiled_sol["contracts"]["ThreatLog.sol"]["ThreatLog"]["metadata"]
    )["output"]["abi"]

    return w3.eth.contract(address=address, abi=abi)

# --------------------------------------------------
# ADD THREAT (CALLED FROM DJANGO)
# --------------------------------------------------

def add_threat(
    threat_id,
    source_ip,
    destination_ip,
    protocol,
    packet_size,
    attack_type,
    detected
):
    contract = get_contract()
    timestamp = int(time.time())

    tx_hash = contract.functions.addThreat(
        int(threat_id),
        source_ip,
        destination_ip,
        int(protocol),
        int(packet_size),
        attack_type,
        bool(detected),
        timestamp
    ).transact()

    return tx_hash.hex()

# --------------------------------------------------
# READ SINGLE THREAT
# --------------------------------------------------

def get_threat(threat_id):
    contract = get_contract()
    return contract.functions.getThreat(int(threat_id)).call()

# --------------------------------------------------
# READ ALL THREATS (HISTORY PAGE)
# --------------------------------------------------

def get_threats():
    contract = get_contract()
    count = contract.functions.getThreatCount().call()

    threats = []
    for i in range(1, count + 1):
        t = contract.functions.getThreat(i).call()
        threats.append({
            "id": i,
            "source_ip": t[0],
            "destination_ip": t[1],
            "protocol": t[2],
            "packet_size": t[3],
            "attack_type": t[4],
            "detected": t[5],
            "timestamp": t[6],
        })
    return threats

# --------------------------------------------------
# COUNT THREATS
# --------------------------------------------------

def get_threat_count():
    contract = get_contract()
    return contract.functions.getThreatCount().call()

# --------------------------------------------------
# MAIN (RUN ONCE)
# --------------------------------------------------

if __name__ == "__main__":
    # Run ONLY ONCE
    #create_contract()
    pass
