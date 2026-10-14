"""Finite desired-message queue; ACK identity is the actual Paho message object.

Only the asyncio owner touches this queue. No MID history and no private Paho
queue manipulation: a new connection discards this queue and rebuilds desired
state from its source. Sent payloads are counted alongside replacements.
"""
from collections import OrderedDict
from dataclasses import dataclass
import time


@dataclass(frozen=True)
class Message:
    topic: str
    payload: str
    retain: bool

    @property
    def size(self): return len(self.topic.encode())+len(self.payload.encode())


class MqttOutbox:
    def __init__(self, *, max_pending=4096, max_bytes=4*1024*1024, max_sent=256):
        self.max_pending,self.max_bytes,self.max_sent=max_pending,max_bytes,max_sent
        self.desired=OrderedDict()
        self.sent={}
        self.client=None
        self.bytes=0

    @property
    def pending(self): return len(self.desired)+len(self.sent)

    @property
    def oldest_age(self):
        return max((time.monotonic()-item[2] for item in self.sent.values()),default=0)

    def bind(self,client):
        if client is not self.client:
            self.desired.clear(); self.sent.clear(); self.bytes=0
            self.client=client

    def offer(self,topic,payload,retain=False):
        value=Message(topic,payload,retain)
        old=self.desired.get(topic)
        sent=self.sent.get(topic)
        if old==value or (old is None and sent and sent[0]==value): return True
        size=self.bytes-(old.size if old else 0)+value.size
        if size>self.max_bytes or (old is None and self.pending>=self.max_pending):
            if old is not None:
                self.desired.pop(topic)
                self.bytes-=old.size
            return False
        self.desired[topic]=value
        self.bytes=size
        return True

    def discard_except(self,topics):
        for topic in self.desired.keys()-topics:
            self.bytes-=self.desired.pop(topic).size

    def acknowledgements(self):
        result=[]
        for topic,(message,info,started) in list(self.sent.items()):
            if info.is_published():
                del self.sent[topic]; self.bytes-=message.size
                result.append(message)
        return result

    def drain(self):
        for topic,message in list(self.desired.items()):
            if len(self.sent)>=self.max_sent: break
            if topic in self.sent: continue
            info=self.client.publish(topic,message.payload,qos=1,retain=message.retain)
            if info.rc!=0: raise ValueError('MQTT publish failed')
            del self.desired[topic]
            self.sent[topic]=(message,info,time.monotonic())
