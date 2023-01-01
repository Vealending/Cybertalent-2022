import ecdsa
import hashlib

def extract_r_s(filename):

    with open(filename, "rb") as f:
        file_contents = f.read()

    sig_start = len(file_contents) - 64
    hash = int(hashlib.sha256(file_contents[:sig_start]).hexdigest(), base=16)
    r, s = ecdsa.util.sigdecode_string(file_contents[sig_start:], ecdsa.SECP256k1.order)

    return r, s, hash

r1, s1, h1 = extract_r_s("test.txt_signed")
r2, s2, h2 = extract_r_s("missile.1.3.37.fw")

print(f"r1: {r1}\nr2: {r2}\nh1: {h1}\n\ns1: {s1}\ns2: {s2}\nh2: {h2}\n")

order = ecdsa.SECP256k1.generator.order()
valinv = ecdsa.numbertheory.inverse_mod(r1 * (s1 - s2), order)
priv_key = ((s2 * h1 - s1 * h2) * (valinv)) % order

print ("Private key: ", priv_key)

with open("privkey.pem", "wb") as f:
    f.write(ecdsa.SigningKey.from_secret_exponent(priv_key, curve=ecdsa.SECP256k1).to_pem())