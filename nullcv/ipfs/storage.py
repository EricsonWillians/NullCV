"""IPFS storage integration for NullCV."""
import ipfshttpclient
import json
import hashlib
from typing import Any, Dict, Optional
import aiohttp
import asyncio

from nullcv.core.config import settings

class IPFSStorage:
    """Service for storing and retrieving data from IPFS."""
    
    def __init__(self):
        self.api_url = settings.IPFS_API_URL
    
    async def add_json(self, data: Dict[str, Any]) -> str:
        """
        Add JSON data to IPFS.
        
        Args:
            data: Dictionary to store on IPFS
            
        Returns:
            IPFS content hash (CID)
        """
        json_str = json.dumps(data)
        
        async with aiohttp.ClientSession() as session:
            endpoint = f"{self.api_url}/add"
            form = aiohttp.FormData()
            form.add_field('file', json_str, 
                          filename='data.json',
                          content_type='application/json')
            
            async with session.post(endpoint, data=form) as response:
                if response.status != 200:
                    raise Exception(f"IPFS add failed: {await response.text()}")
                
                result = await response.json()
                return result['Hash']
    
    async def get_json(self, ipfs_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve JSON data from IPFS.
        
        Args:
            ipfs_hash: IPFS content hash (CID)
            
        Returns:
            Dictionary with retrieved data or None if not found
        """
        try:
            async with aiohttp.ClientSession() as session:
                endpoint = f"{self.api_url}/cat?arg={ipfs_hash}"
                
                async with session.post(endpoint) as response:
                    if response.status != 200:
                        return None
                    
                    content = await response.text()
                    return json.loads(content)
        except Exception:
            return None
    
    async def add_work_proof(self, 
                           user_id: str, 
                           project_id: str, 
                           content: bytes, 
                           metadata: Dict[str, Any]) -> Dict[str, str]:
        """
        Store work proof on IPFS with metadata.
        
        Args:
            user_id: ID of the user who completed the work
            project_id: ID of the project
            content: Binary content of the work
            metadata: Additional metadata about the work
            
        Returns:
            Dictionary with content hash and metadata hash
        """
        # Create content hash
        content_hash = hashlib.sha256(content).hexdigest()
        
        # Add metadata
        full_metadata = {
            **metadata,
            "user_id": user_id,
            "project_id": project_id,
            "content_hash": content_hash,
            "timestamp": import_time(),
        }
        
        # Store content on IPFS
        async with aiohttp.ClientSession() as session:
            content_endpoint = f"{self.api_url}/add"
            content_form = aiohttp.FormData()
            content_form.add_field('file', content, 
                          filename='work_content',
                          content_type='application/octet-stream')
            
            async with session.post(content_endpoint, data=content_form) as response:
                if response.status != 200:
                    raise Exception(f"IPFS add failed: {await response.text()}")
                
                content_result = await response.json()
                content_cid = content_result['Hash']
        
        # Add link to content in metadata
        full_metadata["ipfs_cid"] = content_cid
        
        # Store metadata on IPFS
        metadata_cid = await self.add_json(full_metadata)
        
        return {
            "content_cid": content_cid,
            "metadata_cid": metadata_cid,
            "content_hash": content_hash
        }
