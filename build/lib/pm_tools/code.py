import os
import json
import base64
import tkinter as tk
from tkinter import simpledialog
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import subprocess
import string
import random

VAULT_FILE = os.path.expanduser("~/.config/pm/tools.json")
os.makedirs(os.path.dirname(VAULT_FILE), exist_ok=True)

ITERATIONS = 600000
KEY_LEN = 32
VERIFY = "ok"


def must(x):
    return x is not None and x != ""


def b64e(x):
    return base64.b64encode(x).decode()


def b64d(x):
    return base64.b64decode(x)


def derive_key(p, s):
    return PBKDF2(p, s, dkLen=KEY_LEN, count=ITERATIONS, hmac_hash_module=SHA256)


def enc(t, k):
    c = AES.new(k, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(t.encode())
    return {"n": b64e(c.nonce), "t": b64e(tag), "d": b64e(ct)}


def dec(x, k):
    try:
        c = AES.new(k, AES.MODE_GCM, nonce=b64d(x["n"]))
        return c.decrypt_and_verify(b64d(x["d"]), b64d(x["t"])).decode()
    except:
        return None


def load():
    if not os.path.exists(VAULT_FILE):
        return None
    try:
        return json.load(open(VAULT_FILE))
    except:
        return None


def save(v):
    json.dump(v, open(VAULT_FILE, "w"), indent=2)


def gen(n=20):
    c = string.ascii_letters + string.digits + "!@#$%^&*-_+=?"
    return "".join(random.choice(c) for _ in range(n))


def clip(x):
    try:
        if os.name == "posix":
            subprocess.run("pbcopy", text=True, input=x)
        elif os.name == "nt":
            subprocess.run("clip", text=True, input=x, shell=True)
    except:
        pass


def ask(t, m, s=None):
    return simpledialog.askstring(t, m, show=s)


class PasswordManager:

    def __init__(self, ui):
        self.ui = ui
        self.vault = None
        self.key = None

        self.out = tk.Text(ui, height=18, width=65)
        self.out.pack()

        self.cmd = tk.Entry(ui, width=65)
        self.cmd.pack()
        self.cmd.bind("<Return>", lambda e: self.run())

        self.log("init / login <password> / help")

    def log(self, t):
        self.out.insert(tk.END, t + "\n")
        self.out.see(tk.END)

    def run(self):
        cmd = self.cmd.get().strip()
        self.cmd.delete(0, tk.END)
        if not cmd:
            return
        self.log("> " + cmd.upper())
        self.dispatch(cmd)

    def dispatch(self, cmd):
        parts = cmd.split()
        c = parts[0].lower()

        if c == "help":
            self.help()
        elif c == "init":
            self.init()
        elif c == "login":
            self.login(parts)
        elif c == "add":
            self.add(parts)
        elif c == "list":
            self.list()
        elif c == "get":
            self.get(parts)
        elif c == "delete":
            self.delete(parts)
        elif c == "copy":
            self.copy(parts)
        elif c == "gen":
            self.log(gen(int(parts[1]) if len(parts) > 1 else 20))
        else:
            self.log("unknown command")

    def help(self):
        self.log("INIT")
        self.log("LOGIN <password>")
        self.log("ADD <name>")
        self.log("LIST")
        self.log("GET <name>")
        self.log("DELETE <name>")
        self.log("COPY <name>")
        self.log("GEN [len]")

    def init(self):
        if os.path.exists(VAULT_FILE):
            self.log("vault exists")
            return

        p1 = ask("Password Manager", "password:", "•")
        if not must(p1):
            self.log("cancelled")
            return

        p2 = ask("Password Manager", "confirm:", "•")
        if not must(p2):
            self.log("cancelled")
            return

        if p1 != p2:
            self.log("mismatch")
            return

        salt = get_random_bytes(16)
        key = derive_key(p1, salt)

        v = {"salt": b64e(salt), "verify": enc(VERIFY, key), "data": {}}
        save(v)
        self.log("created")

    def login(self, parts):
        v = load()
        if not v:
            self.log("no vault")
            return

        p = parts[1] if len(parts) > 1 else ask("Password Manager", "password:", "•")
        if not must(p):
            self.log("cancelled")
            return

        key = derive_key(p, b64d(v["salt"]))

        if dec(v["verify"], key) != "ok":
            self.log("wrong password")
            return

        self.vault = v
        self.key = key
        self.log("logged in")

    def add(self, parts):
        if not self.ok():
            return

        if len(parts) < 2:
            self.log("usage: add <name>")
            return

        name = parts[1]

        u = ask("Password Manager", "user:")
        if not must(u):
            self.log("cancelled")
            return

        p = ask("Password Manager", "password:")
        if not must(p):
            self.log("cancelled")
            return

        self.vault["data"][name] = enc(f"{u}:{p}", self.key)
        save(self.vault)
        self.log("saved")

    def list(self):
        if not self.ok():
            return
        for k in self.vault["data"]:
            self.log(k)

    def get(self, parts):
        if not self.ok():
            return
        if len(parts) < 2:
            self.log("usage: get <name>")
            return

        name = parts[1]
        v = self.vault["data"].get(name)
        if not v:
            self.log("not found")
            return

        u, p = dec(v, self.key).split(":")
        self.log(f"{name} -> {u} / {p}")

    def delete(self, parts):
        if not self.ok():
            return
        if len(parts) < 2:
            self.log("usage: delete <name>")
            return

        self.vault["data"].pop(parts[1], None)
        save(self.vault)
        self.log("deleted")

    def copy(self, parts):
        if not self.ok():
            return
        if len(parts) < 2:
            self.log("usage: copy <name>")
            return

        v = self.vault["data"].get(parts[1])
        if not v:
            self.log("not found")
            return

        p = dec(v, self.key).split(":")[1]
        clip(p)
        self.log("copied")

    def ok(self):
        if not self.vault or not self.key:
            self.log("login first")
            return False
        return True


root = tk.Tk()
root.title("Password Manager")
PasswordManager(root)
root.mainloop()
