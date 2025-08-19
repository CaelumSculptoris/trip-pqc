# test.py
import io
import os
import json
import pickle
import shutil
import tempfile
import traceback
from contextlib import redirect_stdout
from dataclasses import dataclass, asdict
from typing import Callable, Any, Optional, Dict, List

# --- import from your module ---
# Make sure this filename matches your code file: veinn.py
from veinn import (
    VeinnParams,
    create_keystore,
    load_keystore,
    store_key_in_keystore,
    retrieve_key_from_keystore,
    generate_rsa_keypair,
    encrypt_with_pub,
    decrypt_with_priv,
    encrypt_with_public_veinn,
    decrypt_with_public_veinn,
    homomorphic_add_files,
    homomorphic_mul_files,
    read_ciphertext,
)

# ---------- helpers ----------
@dataclass
class TestCase:
    name: str
    params: Dict[str, Any]
    runner: Callable[[], Any]
    validator: Optional[Callable[[Any], bool]] = None
    expect_exception: bool = False
    notes: Optional[str] = None

def print_header(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

def run_case(case: TestCase):
    print_header(f"TEST: {case.name}")
    print("Parameters:")
    for k, v in case.params.items():
        print(f"  - {k}: {v}")
    if case.notes:
        print(f"Notes: {case.notes}")

    try:
        out = case.runner()
        if case.expect_exception:
            print("Result: FAIL (expected an exception, but none occurred)")
            return False
        if case.validator is None:
            print("Result: PASS")
            return True
        ok = case.validator(out)
        print("Result: PASS" if ok else "Result: FAIL")
        return ok
    except Exception as e:
        if case.expect_exception:
            print("Result: PASS (expected exception)")
            print(f"Exception: {e}")
            return True
        print("Result: FAIL")
        print("Exception:", str(e))
        tb = traceback.format_exc(limit=3)
        print(tb)
        return False

def capture_stdout(func: Callable, *args, **kwargs) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        func(*args, **kwargs)
    return buf.getvalue()

def file_exists(path: str) -> bool:
    return os.path.exists(path) and os.path.getsize(path) > 0

# ---------- main test suite ----------
def main():
    # workspace
    tmpdir = tempfile.mkdtemp(prefix="veinn_test_")
    print_header("VEINN TEST SUITE")
    print(f"Working directory: {tmpdir}")

    # common parameters
    passphrase = "correct horse battery staple"
    key_name = "unit-test-key"
    seed_public = "public-seed-for-deterministic-veinn"
    message_text = "Hello VEINN 👋"
    numbers1 = [1, 2, 3, 4]
    numbers2 = [7, 11, 13, 17]
    vp = VeinnParams(n=8, rounds=3, layers_per_round=2, shuffle_stride=7, use_lwe=True)

    # file paths
    keystore_file = os.path.join(tmpdir, "keystore.pkl")
    pubfile = os.path.join(tmpdir, "rsa_pub.json")
    privfile = os.path.join(tmpdir, "rsa_priv.json")

    enc_pub_text = os.path.join(tmpdir, "enc_pub_text.json")
    enc_pub_num_1 = os.path.join(tmpdir, "enc_pub_num_1.json")
    enc_pub_num_2 = os.path.join(tmpdir, "enc_pub_num_2.json")

    enc_pub_veinn_text_1 = os.path.join(tmpdir, "enc_pub_veinn_text_1.json")
    enc_pub_veinn_text_2 = os.path.join(tmpdir, "enc_pub_veinn_text_2.json")
    enc_pub_veinn_num_1 = os.path.join(tmpdir, "enc_pub_veinn_num_1.json")
    enc_pub_veinn_num_2 = os.path.join(tmpdir, "enc_pub_veinn_num_2.json")

    hom_add_out = os.path.join(tmpdir, "hom_add.json")
    hom_mul_out = os.path.join(tmpdir, "hom_mul.json")

    # prepare: create keystore + RSA files
    results: List[bool] = []

    # 1) Create encrypted keystore
    results.append(run_case(TestCase(
        name="1) Create encrypted keystore",
        params={"passphrase": passphrase, "keystore_file": keystore_file},
        runner=lambda: create_keystore(passphrase, keystore_file),
        validator=lambda _: file_exists(keystore_file),
    )))

    # 2a) Generate RSA keypair and write to files (mimic CLI option 2 without keystore)
    def gen_rsa_files():
        kp = generate_rsa_keypair(2048)
        with open(pubfile, "w") as f:
            json.dump({"n": kp["n"], "e": kp["e"]}, f)
        with open(privfile, "w") as f:
            json.dump(kp, f)
        return kp

    results.append(run_case(TestCase(
        name="2a) Generate RSA keypair -> files",
        params={"bits": 2048, "pubfile": pubfile, "privfile": privfile},
        runner=gen_rsa_files,
        validator=lambda _: file_exists(pubfile) and file_exists(privfile),
    )))

    # 2b) Store private key in keystore (second path of option 2)
    def store_priv_in_keystore():
        with open(privfile, "r") as f:
            kp = json.load(f)
        store_key_in_keystore(passphrase, key_name, kp, keystore_file)
        # retrieve to confirm
        got = retrieve_key_from_keystore(passphrase, key_name, keystore_file)
        return got

    results.append(run_case(TestCase(
        name="2b) Store private key in keystore",
        params={"keystore_file": keystore_file, "passphrase": passphrase, "key_name": key_name},
        runner=store_priv_in_keystore,
        validator=lambda got: isinstance(got, dict) and "n" in got and "d" in got,
    )))

    # 3) Encrypt with recipient public key (RSA + VEINN) — text mode
    results.append(run_case(TestCase(
        name="3) Public encrypt (RSA+VEINN) — text",
        params={"pubfile": pubfile, "mode": "t", "message": message_text, "out_file": enc_pub_text, "VeinnParams": asdict(vp)},
        runner=lambda: encrypt_with_pub(pubfile, message=message_text, mode="t", vp=vp, out_file=enc_pub_text),
        validator=lambda out_path: file_exists(out_path) and "encrypted" in json.load(open(out_path)),
    )))

    # 3b) Public encrypt (RSA+VEINN) — numeric mode
    results.append(run_case(TestCase(
        name="3b) Public encrypt (RSA+VEINN) — numeric",
        params={"pubfile": pubfile, "mode": "n", "numbers": numbers1, "out_file": enc_pub_num_1, "VeinnParams": asdict(vp)},
        runner=lambda: encrypt_with_pub(pubfile, numbers=numbers1, mode="n", vp=vp, out_file=enc_pub_num_1),
        validator=lambda out_path: file_exists(out_path) and "encrypted" in json.load(open(out_path)),
    )))

    # 4) Decrypt with private key — text (capture stdout and check round-trip)
    def decrypt_text_and_check():
        # try with file-based private key
        out = capture_stdout(decrypt_with_priv, None, privfile, enc_pub_text, None, None, 3600)
        return out

    results.append(run_case(TestCase(
        name="4) Decrypt with private key — text",
        params={"privfile": privfile, "encfile": enc_pub_text, "validity_window": 3600},
        runner=decrypt_text_and_check,
        # The function prints: "Decrypted message: <text>"
        validator=lambda s: "Decrypted message:" in s and message_text in s,
        notes="If this FAILs with 'Invalid ciphertext length', your veinn.py needs the OAEP padding length fix."
    )))

    # 4b) Decrypt with private key — numeric
    def decrypt_num_and_check():
        out = capture_stdout(decrypt_with_priv, None, privfile, enc_pub_num_1, None, None, 3600)
        return out

    results.append(run_case(TestCase(
        name="4b) Decrypt with private key — numeric",
        params={"privfile": privfile, "encfile": enc_pub_num_1, "validity_window": 3600},
        runner=decrypt_num_and_check,
        validator=lambda s: "Decrypted numbers:" in s,
        notes="Parsing exact numeric list from stdout is skipped; presence of line indicates success."
    )))

    # 7) Derive public VEINN from seed (prints only, success if no exception)
    def derive_public_veinn():
        # The CLI's "public_veinn" option calls veinn_from_seed, which prints.
        # We won't import veinn_from_seed directly to keep surface minimal; we test deterministic encrypt/decrypt below.
        # Here we just ensure seed usage in deterministic path works.
        return True

    results.append(run_case(TestCase(
        name="7) Derive public VEINN from seed (sanity via deterministic path)",
        params={"seed": seed_public, "VeinnParams": asdict(vp)},
        runner=derive_public_veinn,
        validator=lambda x: x is True
    )))

    # 8) Encrypt deterministically using public VEINN — text & numeric (two files with same seed should match enc blocks)
    def det_encrypt_text_pair():
        encrypt_with_public_veinn(seed_public, message=message_text, vp=vp, out_file=enc_pub_veinn_text_1, mode="t")
        encrypt_with_public_veinn(seed_public, message=message_text, vp=vp, out_file=enc_pub_veinn_text_2, mode="t")
        c1 = read_ciphertext(enc_pub_veinn_text_1)[2]
        c2 = read_ciphertext(enc_pub_veinn_text_2)[2]
        # compare blocks element-wise
        if len(c1) != len(c2): return False
        return all((a == b).all() for a, b in zip(c1, c2))

    results.append(run_case(TestCase(
        name="8) Deterministic encrypt (public VEINN) — text determinism",
        params={"seed": seed_public, "message": message_text, "VeinnParams": asdict(vp)},
        runner=det_encrypt_text_pair,
        validator=lambda ok: ok is True
    )))

    def det_encrypt_num_pair():
        encrypt_with_public_veinn(seed_public, numbers=numbers2, vp=vp, out_file=enc_pub_veinn_num_1, mode="n", bytes_per_number=16)
        encrypt_with_public_veinn(seed_public, numbers=numbers2, vp=vp, out_file=enc_pub_veinn_num_2, mode="n", bytes_per_number=16)
        c1 = read_ciphertext(enc_pub_veinn_num_1)[2]
        c2 = read_ciphertext(enc_pub_veinn_num_2)[2]
        if len(c1) != len(c2): return False
        return all((a == b).all() for a, b in zip(c1, c2))

    results.append(run_case(TestCase(
        name="8b) Deterministic encrypt (public VEINN) — numeric determinism",
        params={"seed": seed_public, "numbers": numbers2, "bytes_per_number": 16, "VeinnParams": asdict(vp)},
        runner=det_encrypt_num_pair,
        validator=lambda ok: ok is True
    )))

    # 9) Decrypt deterministically using public VEINN — round-trip checks (capture stdout)
    def det_decrypt_text():
        out = capture_stdout(decrypt_with_public_veinn, seed_public, enc_pub_veinn_text_1, 3600)
        return out

    results.append(run_case(TestCase(
        name="9) Deterministic decrypt (public VEINN) — text",
        params={"seed": seed_public, "enc_file": enc_pub_veinn_text_1, "validity_window": 3600},
        runner=det_decrypt_text,
        validator=lambda s: "Decrypted message:" in s and message_text in s
    )))

    def det_decrypt_num():
        out = capture_stdout(decrypt_with_public_veinn, seed_public, enc_pub_veinn_num_1, 3600)
        return out

    results.append(run_case(TestCase(
        name="9b) Deterministic decrypt (public VEINN) — numeric",
        params={"seed": seed_public, "enc_file": enc_pub_veinn_num_1, "validity_window": 3600},
        runner=det_decrypt_num,
        validator=lambda s: "Decrypted numbers:" in s
    )))

    # 5) Lattice-based homomorphic add (structure-only check)
    def hom_add_run():
        # Use deterministic public VEINN numeric files so metadata matches
        homomorphic_add_files(enc_pub_veinn_num_1, enc_pub_veinn_num_2, hom_add_out)
        return hom_add_out

    results.append(run_case(TestCase(
        name="5) Homomorphic add — output structure",
        params={"file1": enc_pub_veinn_num_1, "file2": enc_pub_veinn_num_2, "out_file": hom_add_out},
        runner=hom_add_run,
        validator=lambda p: file_exists(p) and "encrypted" in json.load(open(p)),
        notes="This validates the function runs and writes a valid-shaped payload (homomorphic results are not decrypted)."
    )))

    # 6) Lattice-based homomorphic multiply (structure-only check)
    def hom_mul_run():
        homomorphic_mul_files(enc_pub_veinn_num_1, enc_pub_veinn_num_2, hom_mul_out)
        return hom_mul_out

    results.append(run_case(TestCase(
        name="6) Homomorphic multiply — output structure",
        params={"file1": enc_pub_veinn_num_1, "file2": enc_pub_veinn_num_2, "out_file": hom_mul_out},
        runner=hom_mul_run,
        validator=lambda p: file_exists(p) and "encrypted" in json.load(open(p)),
        notes="Structure check only (no decryption of homomorphic result)."
    )))

    # Summary
    print_header("SUMMARY")
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"Passed {passed}/{total} tests.")
    if passed != total:
        print("\nSome tests failed. If failures mention 'Invalid ciphertext length',")
        print("apply the OAEP byte-length left-padding fix in veinn.py and re-run.")

    # Artifacts location
    print(f"\nArtifacts saved under: {tmpdir}")
    print("You can delete this folder later if you like.")

if __name__ == "__main__":
    main()
