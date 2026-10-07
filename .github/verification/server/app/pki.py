"""Private FRP CA; atomic leaf bundle avoids mismatched key/cert on interruption."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from shared.files import atomic_write
from shared.validation import domain


@dataclass(frozen=True)
class PKI:
    ca: Path
    cert: Path
    key: Path
    renewed: bool


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def ensure_pki(directory, hostname, now=None):
    hostname = domain(hostname)
    now = now or datetime.now(timezone.utc)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ca_path, ca_key_path = directory/'ca.pem', directory/'ca.key'
    leaf_path = directory/'server.pem'
    if ca_path.exists() != ca_key_path.exists():
        raise ValueError('Incomplete CA; restore saved identity')
    if ca_path.exists():
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        if ca.public_key().public_numbers() != ca_key.public_key().public_numbers():
            raise ValueError('CA identity mismatch')
        if ca.not_valid_after_utc < now + timedelta(days=100):
            raise ValueError('CA expires soon; trusted re-enrollment required')
    else:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'HA Tunnel private CA')])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
              .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
              .sign(ca_key,hashes.SHA256()))
        atomic_write(ca_key_path,private_bytes(ca_key))
        atomic_write(ca_path,ca.public_bytes(serialization.Encoding.PEM))
    if leaf_path.exists():
        leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
        leaf.verify_directly_issued_by(ca)
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        leaf_key = serialization.load_pem_private_key(leaf_path.read_bytes(),password=None)
        if leaf.public_key().public_numbers() != leaf_key.public_key().public_numbers():
            raise ValueError('Leaf identity mismatch')
        if (names.get_values_for_type(x509.DNSName) == [hostname] and
                leaf.not_valid_before_utc <= now and leaf.not_valid_after_utc > now+timedelta(days=30)):
            return PKI(ca_path,leaf_path,leaf_path,False)
    key = rsa.generate_private_key(public_exponent=65537,key_size=3072)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
            .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .sign(ca_key,hashes.SHA256()))
    atomic_write(leaf_path,leaf.public_bytes(serialization.Encoding.PEM)+private_bytes(key))
    return PKI(ca_path,leaf_path,leaf_path,True)
