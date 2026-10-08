"""Send the local owner's code only to a reviewed CI run's ephemeral recipient."""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--proof-directory',type=Path,required=True)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--source-commit',required=True)
    args=parser.parse_args()
    assert re.fullmatch('[0-9]+',args.run_id) and re.fullmatch('[a-f0-9]{40}',args.source_commit)
    recipient=json.loads((args.proof_directory/'recipient.json').read_text())
    current=json.loads(Path('/workspace/malguard.github.io/release/malguard-current-release.json').read_text())
    assert recipient['schema']==1 and recipient['runId']==args.run_id and recipient['sourceCommit']==args.source_commit
    assert recipient['build']==current['build'] and recipient['sha256']==current['sha256']
    public=serialization.load_pem_public_key(recipient['publicKey'].encode())
    assert isinstance(public,rsa.RSAPublicKey) and public.key_size==3072
    code=re.sub(r'[-\s]','',Path('/workspace/.private-malguard-1.3/site-gated-1.3.1/download-code').read_text().strip().upper())
    assert re.fullmatch('MG[A-Z2-7]{32}',code)
    payload=json.dumps({'runId':args.run_id,'sha256':current['sha256'],'code':code},separators=(',',':')).encode()
    cipher=public.encrypt(payload,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    wrapped={'schema':1,'runId':args.run_id,'recipientSha256':hashlib.sha256(recipient['publicKey'].encode()).hexdigest(),'ciphertext':base64.b64encode(cipher).decode()}
    (args.proof_directory/'wrapped-code.json').write_text(json.dumps(wrapped,indent=2)+'\n')
    print('Download code wrapped for reviewed ephemeral CI recipient; no plaintext code published')

if __name__=='__main__':main()
