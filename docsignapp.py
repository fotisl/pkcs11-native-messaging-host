#!/usr/bin/python3
# Chrome native messaging host for PKCS#11 signing
# Fotis Loukos <me@fotisl.com>

import PyKCS11
import base64
import hashlib
import json
import sys
import struct
import threading
import queue
import os.path
import tkinter
import tkinter.simpledialog
import tkinter.messagebox
import tkinter.filedialog

if sys.platform == "linux":
    pkcs11libs = ["/usr/lib/libeTPkcs11.so", "/usr/lib/pkcs11/libgclib.so", None]
    libfiletypes = [("Shared objects", "*.so")]
elif sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    pkcs11libs = ["C:\\Windows\\System32\\eTPKCS11.dll", "C:\\Program Files (x86)\\Gemalto\\Classic Client\\BIN\\GCLIB.DLL", "C:\\Program Files\\Gemalto\\Classic Client\\BIN\\GCLIB.DLL", None]
    libfiletypes = [("Dynamic Link Libraries", "*.dll")]
elif sys.platform == "darwin":
    pkcs11libs = ["/usr/local/lib/libeTPkcs11.dylib", "/usr/local/lib/ClassicClient/libgclib.dylib", None]
    libfiletypes = [("Dynamic Libraries", "*.dylib")]
else:
    tkinter.messagebox.showinfo("Error", "Error: unsupported platform")
    sys.exit(1)

cachedpin = None
cachedtoken = None

def sign(text):
    global cachedpin, cachedtoken

    pkcs11 = PyKCS11.PyKCS11Lib()

    for lib in pkcs11libs:
        if lib is None:
            lib = tkinter.filedialog.askopenfilename(title = "Please enter path to PKCS#11 library", filetypes = libfiletypes)
            try:
                pkcs11.load(lib)
            except:
                tkinter.messagebox.showinfo("Error", "Error: Cannot load PKCS#11 library")
                return None

        if not os.path.exists(lib):
            continue

        try:
            pkcs11.load(lib)
        except:
            continue

        slots = pkcs11.getSlotList()

        for s in slots:
            try:
                i = pkcs11.getTokenInfo(s)
            except:
                continue

            session = pkcs11.openSession(s)

            if cachedtoken == i.label.decode("utf8").strip():
                try:
                    session.login(pin = cachedpin)
                except:
                    cachedtoken = None

            if cachedtoken is None or cachedtoken != i.label.decode("utf8").strip():
                while True:
                    pin = tkinter.simpledialog.askstring("Enter PIN", "Please enter PIN for Token with label '" + i.label.decode("utf8").strip() + "'", show = "*")

                    if pin == "":
                        break

                    try:
                        session.login(pin = pin)
                        cachedtoken = i.label.decode("utf8").strip()
                        cachedpin = pin
                        break
                    except Exception as e:
                        tkinter.messagebox.showinfo("Error", "Error: " + str(e) + "\nTry logging in again.")

            certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
            pkey = None
            for c in certs:
                cdict = c.to_dict()
                issuer = "".join([chr(s) for s in cdict["CKA_ISSUER"]])
                if issuer.find("Aristotle University of Thessaloniki Central CA") == -1:
                    continue
                subject = "".join([chr(s) for s in cdict['CKA_SUBJECT']])
                if subject.find("Class B - Private Key created and stored in software CSP") == -1:
                    continue
                certid = cdict["CKA_ID"]

                pkeys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, certid)])
                if len(pkeys) != 1:
                    tkinter.messagebox.showinfo("Error", "Error: Could not find a single private key for this certificate")
                    continue

                pkey = pkeys[0]
                cert = base64.b64encode(bytes(cdict["CKA_VALUE"])).decode("utf8")
                break

            if pkey is None:
                continue

            sig = session.sign(pkey, text)
            session.closeSession()

            return (sig, cert)

    return None

def send_msg(message):
    sys.stdout.buffer.write(struct.pack('I', len(message)))
    sys.stdout.write(message)
    sys.stdout.flush()

def send_err(message):
    send_msg(json.dumps({"error": message}))

def send_sig(message):
    plain = message["message"]

    if "srcenc" in message:
        if message["srcenc"] == "base64":
            plain = base64.b64decode(plain)
        elif message["srcenc"] == "base32":
            plain = base64.b32decode(plain)
        elif message["srcenc"] == "base16":
            plain = base64.b16decode(plain)
        elif message["srcenc"] == "plain":
            plain = bytes(plain, "utf8")
        else:
            send_err("Invalid source encoding")
            return

    if "hash" in message:
        if message["hash"] == "md5":
            plain = hashlib.md5(plain).digest()
        elif message["hash"] == "sha1":
            plain = hashlib.sha1(plain).digest()
        elif message["hash"] == "sha256":
            plain = hashlib.sha256(plain).digest()
        elif message["hash"] == "sha384":
            plain = hashlib.sha384(plain).digest()
        elif message["hash"] == "sha512":
            plain = hashlib.sha512(plain).digest()
        elif message["hash"] == "none":
            pass
        else:
            send_err("Invalid hash algorithm specified")
            return

    sig = sign(plain)

    if sig is None:
        send_err("Cannot sign message")
        return

    if "dstenc" in message:
        if message["dstenc"] == "base64":
            finalsig = base64.b64encode(bytes(''.join([chr(i) for i in sig[0]]), "latin1")).decode("utf8")
        elif message["dstenc"] == "base32":
            finalsig = base64.b32encode(bytes(''.join([chr(i) for i in sig[0]]), "latin1")).decode("utf8")
        elif message["dstenc"] == "base16":
            finalsig = base64.b16encode(bytes(''.join([chr(i) for i in sig[0]]), "latin1")).decode("utf8")
        elif message["dstenc"] == "hex":
            finalsig = "".join(['%02x' % i for i in sig[0]])
        else:
            send_err("Invalid destination encoding")
            return
    else:
        finalsig = "".join(['%02x' % i for i in sig[0]])

    resp = {"signature": finalsig}
    if "includecert" in message and message["includecert"] == 1:
        resp["cert"] = sig[1]

    send_msg(json.dumps(resp))

def readfunc(q):
    while True:
        msglenbuf = bytearray(4)

        if sys.stdin.buffer.readinto(msglenbuf) != 4:
            q.put(None)
            sys.exit(0)

        msglen = struct.unpack('i', bytes(msglenbuf))[0]
        msgbuf = bytearray(msglen)
        sys.stdin.buffer.readinto(msgbuf)
        msg = json.loads(msgbuf.decode('utf-8'))
        q.put(msg)

def Main():
    window = tkinter.Tk()
    window.wm_withdraw()

    q = queue.Queue()

    thread = threading.Thread(target = readfunc, args=(q,))
    thread.daemon = True
    thread.start()

    while True:
        msg = q.get()

        if msg is None:
            sys.exit(0)

        if "message" not in msg or msg["message"] == "":
            send_err("Cannot find valid message to sign")
        else:
            send_sig(msg)

        q.task_done()

if __name__ == '__main__':
    Main()
