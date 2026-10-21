"""Active Dolev-Yao channel and session drivers for the security tests.

The adversary controls the wire completely: it sees every message, can drop, reorder,
replay, modify, and inject, and it can ask any node to hand over state at any point
(the exposure oracle of the ACCE model). Nodes only ever talk through `Net`.
"""
import os
import copy

from . import ibs, proto
from .proto import Error, Session


class Net:
    def __init__(self):
        self.wire = []          # log of delivered messages: (frm, to, msg)
        self.blocked = set()    # (frm, to) -> drop everything

    def send(self, frm, to, msg):
        rec = (frm, to, _clone(msg))
        if (frm, to) in self.blocked:
            self.wire.append(("DROPPED", frm, to, _clone(msg)))
            raise Error("channel: delivery blocked to %s" % (to,))
        self.wire.append(rec)
        return rec[2]

    def forget(self, frm, to):
        self.blocked.discard((frm, to))


def _clone(msg):
    out = {}
    for k, v in msg.items():
        out[k] = v if not isinstance(v, dict) else _clone(v)
    return out


class Fleet:
    """PKG plus registered nodes: everything the protocol needs before a session."""

    def __init__(self):
        self.mpk, self.msk = ibs.setup()
        self.keys = {}

    def register(self, identity):
        self.keys[identity] = ibs.extract(self.mpk, self.msk, identity)
        return self.keys[identity]

    def node(self, identity, role="initiator"):
        if identity not in self.keys:
            self.register(identity)
        return Session(identity, self.keys[identity], role, self.mpk)


def handshake(net, A, B, sigA=None, sigB=None, ss_override=None):
    """Full phase 1 + key confirmation, exactly eq 4-4..4-20."""
    m1 = A.initiate(B.id)
    if sigA is not None:
        m1["sigma"] = sigA
    m1 = net.send(A.id, B.id, m1)
    m2 = B.respond(m1)
    if sigB is not None:
        m2["sigma"] = sigB
    m2 = net.send(B.id, A.id, m2)
    A.finalize(m2)
    macb = net.send(B.id, A.id, {"MACB": B.mac_b})["MACB"]
    A.check = A.key_confirm(macb)
    maca = net.send(A.id, B.id, {"MACA": A.mac_a})["MACA"]
    B.key_confirm(maca)
    return m1, m2


def establish(net, fleet, ida=b"IIOT-GW-0001", idb=b"IIOT-PLC-0042"):
    A = fleet.node(ida, "initiator")
    B = fleet.node(idb, "responder")
    handshake(net, A, B)
    return A, B


def do_epoch(net, A, B):
    """One asymmetric ratchet round: MsgA then MsgB (eq 4-24..4-30)."""
    ma = A.start_epoch()
    ma = net.send(A.id, B.id, ma)
    mb = B.accept_epoch_a(ma)
    mb = net.send(B.id, A.id, mb)
    A.accept_epoch_b(mb)
    return ma, mb


def traffic(net, A, B, n, plaintext=b"setpoint=41.5"):
    msgs = []
    for _ in range(n):
        m = A.encrypt(plaintext)
        m = net.send(A.id, B.id, m)
        msgs.append(m)
        B.decrypt(m)
    return msgs
