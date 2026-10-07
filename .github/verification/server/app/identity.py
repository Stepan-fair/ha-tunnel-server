"""Local RS256 issuer for native FRP OIDC, no external identity provider."""
import json
import time
from pathlib import Path
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from shared.files import atomic_write


class Authority:
    def __init__(self, path: Path, issuer: str):
        self.issuer = issuer
        path = Path(path)
        if not path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            atomic_write(path, key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        self.public = self.key.public_key()

    def issue(self, client_id: str, now: int | None = None, *, generation: int | None = None) -> str:
        now = int(time.time()) if now is None else now
        claims={'iss':self.issuer,'aud':'ha-tunnel','sub':client_id,'iat':now,'nbf':now-5,'exp':now+3600}
        if generation is not None:
            if type(generation) is not int or generation<0: raise ValueError('Invalid generation')
            claims['generation']=generation
        return jwt.encode(claims, self.key,
                          algorithm='RS256', headers={'kid':'ha-tunnel-v1'})

    def claims(self, token: str) -> dict:
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError('Invalid token')
        try:
            claims = jwt.decode(token, self.public, algorithms=['RS256'], audience='ha-tunnel',
                                issuer=self.issuer, options={'require':['iss','aud','sub','exp','iat','nbf']})
            if not isinstance(claims['sub'], str):
                raise ValueError('Invalid subject')
            if 'generation' in claims and (type(claims['generation']) is not int or claims['generation']<0):
                raise ValueError('Invalid generation')
            return claims
        except jwt.PyJWTError as exc:
            raise ValueError('Invalid token') from exc

    def subject(self, token: str) -> str:
        return self.claims(token)['sub']

    def discovery(self):
        return {'issuer':self.issuer,'jwks_uri':self.issuer+'/jwks',
                'id_token_signing_alg_values_supported':['RS256'],
                'subject_types_supported':['public'], 'response_types_supported':['id_token']}

    def jwks(self):
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.public))
        return {'keys':[{**key,'kid':'ha-tunnel-v1','use':'sig','alg':'RS256'}]}
