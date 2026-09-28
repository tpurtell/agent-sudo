#!/usr/bin/env python3
"""Speak the agent-sudo socket protocol exactly like the setuid binary does.

For demos and tests without root: point it at an agent-sudo-hostd socket whose
`allow_peer_uids` includes your uid. Prints every line hostd sends back.

    fake_sudo.py --socket /tmp/moa.sock --context "why" -- apt install -y jq
"""
import argparse, os, pwd, shutil, socket, sys

SAFE = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/:@,+")

def enc(v):
    b = v.encode() if isinstance(v, str) else v
    return "".join(chr(c) if c in SAFE else "%%%02X" % c for c in b)

def dec(s):
    out, i = bytearray(), 0
    while i < len(s):
        if s[i] == "%":
            out.append(int(s[i+1:i+3], 16)); i += 3
        else:
            out.append(ord(s[i])); i += 1
    return out.decode(errors="replace")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--socket", required=True)
    p.add_argument("--context")
    p.add_argument("--session")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--nonblocking", action="store_true")
    p.add_argument("--hostname", default=os.uname().nodename)
    p.add_argument("--no-wait", action="store_true", help="exit after the first reply")
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args()
    cmd = [c for c in a.command if c != "--"] or ["true"]
    exe = cmd[0] if cmd[0].startswith("/") else (shutil.which(cmd[0]) or "/usr/bin/" + cmd[0])
    me = pwd.getpwuid(os.getuid())
    fields = [("mode", "run"), ("nonblocking", "1" if a.nonblocking else "0"), ("interactive", "0"),
              ("pid", str(os.getpid())), ("hostname", a.hostname), ("user", me.pw_name),
              ("uid", str(me.pw_uid)), ("gid", str(me.pw_gid)), ("target_user", "root"),
              ("target_uid", "0"), ("target_group", "root"), ("target_gid", "0"),
              ("timeout_secs", str(a.timeout)), ("launch", "direct"), ("command", exe)]
    fields += [("arg", x) for x in cmd[1:]]
    fields.append(("cwd", os.getcwd()))
    if a.context: fields.append(("context", a.context))
    if a.session: fields.append(("session", a.session))
    block = "agent-sudo-request v=1\n" + "".join(f"{k}={enc(v)}\n" for k, v in fields) + "\n"
    s = socket.socket(socket.AF_UNIX); s.connect(a.socket); s.sendall(block.encode())
    f = s.makefile("r")
    for line in f:
        verb, *rest = line.split()
        kv = dict(r.split("=", 1) for r in rest)
        print(verb, " ".join(f"{k}={dec(v)}" for k, v in kv.items()), flush=True)
        if verb != "pending" or a.no_wait:
            return 0 if verb == "approved" else 1
    return 1

if __name__ == "__main__":
    sys.exit(main())
