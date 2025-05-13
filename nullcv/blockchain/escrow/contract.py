"""Smart contract integration for escrow services."""
from web3 import Web3
from eth_account import Account
import json
from typing import Dict, Any, Optional

from nullcv.core.config import settings

class EscrowContract:
    """Interface to the NullCV escrow smart contract."""
    
    def __init__(self):
        """Initialize connection to Ethereum node."""
        self.w3 = Web3(Web3.HTTPProvider(settings.ETHEREUM_NODE_URL))
        self.contract_address = settings.CONTRACT_ADDRESS
        
        # Load contract ABI
        with open("nullcv/blockchain/contracts/escrow_abi.json") as f:
            contract_abi = json.load(f)
        
        # Initialize contract interface
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=contract_abi
        )
    
    async def create_escrow(
        self, 
        client_address: str, 
        worker_address: str, 
        amount: int,
        project_id: str,
        private_key: str
    ) -> Dict[str, Any]:
        """
        Create a new escrow for a project.
        
        Args:
            client_address: Ethereum address of the client
            worker_address: Ethereum address of the worker
            amount: Amount in wei to escrow
            project_id: Unique project identifier
            private_key: Private key to sign the transaction
        """
        account = Account.from_key(private_key)
        
        # Prepare transaction
        tx = self.contract.functions.createEscrow(
            worker_address,
            project_id,
        ).build_transaction({
            'from': client_address,
            'value': amount,
            'gas': 200000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(client_address),
            'chainId': settings.ETHEREUM_CHAIN_ID,
        })
        
        # Sign and send transaction
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Parse event logs to get escrow ID
        escrow_created_events = self.contract.events.EscrowCreated().process_receipt(tx_receipt)
        if not escrow_created_events:
            raise Exception("Failed to create escrow: Event not found in transaction logs")
        
        escrow_id = escrow_created_events[0]['args']['escrowId']
        
        return {
            "escrow_id": escrow_id,
            "transaction_hash": tx_hash.hex(),
            "client_address": client_address,
            "worker_address": worker_address,
            "amount": amount,
            "project_id": project_id,
            "status": "created"
        }
    
    async def release_payment(
        self, 
        escrow_id: int, 
        sender_address: str,
        private_key: str
    ) -> Dict[str, Any]:
        """
        Release payment from escrow to worker after successful completion.
        
        Args:
            escrow_id: ID of the escrow
            sender_address: Address of the transaction sender (client)
            private_key: Private key to sign the transaction
        """
        # Prepare transaction
        tx = self.contract.functions.releasePayment(
            escrow_id
        ).build_transaction({
            'from': sender_address,
            'gas': 100000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(sender_address),
            'chainId': settings.ETHEREUM_CHAIN_ID,
        })
        
        # Sign and send transaction
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            "escrow_id": escrow_id,
            "transaction_hash": tx_hash.hex(),
            "status": "released"
        }
        
    async def get_escrow_details(self, escrow_id: int) -> Optional[Dict[str, Any]]:
        """
        Get details about an escrow.
        
        Args:
            escrow_id: ID of the escrow
        """
        try:
            escrow = self.contract.functions.escrows(escrow_id).call()
            
            return {
                "escrow_id": escrow_id,
                "client": escrow[0],
                "worker": escrow[1],
                "amount": escrow[2],
                "project_id": escrow[3],
                "released": escrow[4],
                "completed": escrow[5],
                "disputed": escrow[6],
            }
        except Exception:
            return None
