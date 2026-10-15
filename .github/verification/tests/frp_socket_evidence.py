"""Test-only identity/protocol evidence for the IPv4, non-multiplexed FRP fixture."""
from dataclasses import dataclass,field
import json
import os
from pathlib import Path
import re
import socket


@dataclass(frozen=True)
class TcpSocket:
    inode: int
    local: tuple[str,int]
    remote: tuple[str,int]


def established_sockets(pid,port,*,proc_root=Path('/proc')):
    process=proc_root/str(pid)
    inodes=set()
    for fd in (process/'fd').iterdir():
        try: link=os.readlink(fd)
        except FileNotFoundError: continue
        if link.startswith('socket:[') and link.endswith(']'): inodes.add(int(link[8:-1]))
    def endpoint(raw):
        address,number=raw.split(':')
        return socket.inet_ntoa(bytes.fromhex(address)[::-1]),int(number,16)
    result=set()
    for line in (process/'net'/'tcp').read_text().splitlines()[1:]:
        fields=line.split()
        if len(fields)<10: raise ValueError('Malformed proc TCP row')
        inode=int(fields[9])
        if fields[3]!='01' or inode not in inodes: continue
        local=endpoint(fields[1])
        if local[1]==port: result.add(TcpSocket(inode,local,endpoint(fields[2])))
    return result


@dataclass(frozen=True)
class LoginProof:
    socket: TcpSocket
    epoch: str=field(repr=False)
    nonce: str=field(repr=False)


class ControlEvidence:
    def __init__(self,*,max_logins=128):
        if type(max_logins) is not int or not 1<=max_logins<=128:
            raise ValueError('Invalid evidence bound')
        self.max_logins=max_logins
        self.history=[]
        self.activated=set()

    def accept(self,client_address,epoch,nonce,sockets):
        if (not isinstance(client_address,str) or
                not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',client_address) or
                not isinstance(epoch,str) or not re.fullmatch(r'[0-9a-f]{32}',epoch) or
                not isinstance(nonce,str) or not re.fullmatch(r'[0-9a-f]{64}',nonce)):
            raise ValueError('Invalid Login evidence')
        remote=('127.0.0.1',int(client_address.rsplit(':',1)[1]))
        matches=[item for item in sockets if item.remote==remote]
        if (not 1<=remote[1]<=65535 or len(matches)!=1 or len(self.history)>=self.max_logins or
                any(row.epoch==epoch or row.socket==matches[0] for row in self.history)):
            raise ValueError('Unmapped or duplicate Login evidence')
        proof=LoginProof(matches[0],epoch,nonce)
        self.history.append(proof)
        return proof

    def activate(self,epoch):
        if not any(row.epoch==epoch for row in self.history):
            raise ValueError('Unknown control activation')
        self.activated.add(epoch)

    def latest(self,nonce):
        return next((row for row in reversed(self.history) if row.nonce==nonce),None)

    def sample(self,epoch,nonce,sockets):
        # Never filter history to the current owner: a superseded accepted socket
        # still ESTABLISHED is a real duplicate and must remain counted.
        accepted={row.socket for row in self.history}&sockets
        current=next((row for row in self.history if row.epoch==epoch and row.nonce==nonce),None)
        return dict(raw_all=len(sockets),accepted=len(accepted),unclassified=len(sockets-accepted),
                    current_present=current is not None and current.socket in sockets,
                    current_activated=current is not None and current is self.history[-1]
                                      and epoch in self.activated)

    def ready(self,epoch,nonce,sockets):
        state=self.sample(epoch,nonce,sockets)
        return state['accepted']==1 and state['current_present'] and state['current_activated']

    def require_current(self,epoch,nonce,sockets):
        state=self.sample(epoch,nonce,sockets)
        assert state['accepted']==1 and state['current_present'] and state['current_activated'],state
        return state['accepted']


def runtime_process_nonce(path):
    # start writes the candidate before awaiting verify; _launch adds the nonce.
    # Missing fields in that valid intermediate config mean "not launched yet".
    if not path.exists(): return None
    return json.loads(path.read_text()).get('metadatas',{}).get('ha_tunnel_process')


class ReservationClock:
    """Inject one real TTL expiry at the selected process's Login callback."""
    def __init__(self,clock):
        self.clock=clock
        self.offset=0.0
        self.expected_nonce=None

    def __call__(self):
        return self.clock()+self.offset

    def arm(self,expected_nonce):
        if self.expected_nonce is not None: raise ValueError('Expiry already armed')
        self.expected_nonce=expected_nonce

    def before_login(self,nonce):
        if self.expected_nonce is not None and nonce is not None and nonce==self.expected_nonce():
            self.offset+=16  # Production reservation TTL is 15 seconds.
            self.expected_nonce=None
