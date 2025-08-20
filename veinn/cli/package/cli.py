import os
import sys
import json
import time
import argparse
from base64 import b64decode
from .params import VeinnParams, bcolors
from .keystore import create_keystore, store_key_in_keystore, retrieve_key_from_keystore
from .rsa_oaep import generate_rsa_keypair
from .public_api import (
    encrypt_with_pub, decrypt_with_priv,
    veinn_from_seed, encrypt_with_public_veinn, decrypt_with_public_veinn,
)
from .homomorphic import homomorphic_add_files, homomorphic_mul_files

# -----------------------------
# CLI Main with Interactive Menu
# -----------------------------
def menu_generate_keystore():
    passphrase = input("Enter keystore passphrase: ")
    keystore_file = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
    create_keystore(passphrase, keystore_file)

def menu_generate_rsa_keypair():
    bits = int(input("RSA key size in bits (default 2048): ").strip() or 2048)
    pubfile = input("Public key filename (default rsa_pub.json): ").strip() or "rsa_pub.json"
    use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() or "y"
    privfile, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Key name in keystore: ")
    else:
        privfile = input("Private key filename (default rsa_priv.json): ").strip() or "rsa_priv.json"
    keypair = generate_rsa_keypair(bits)
    with open(pubfile, "w") as f:
        json.dump({"n": keypair["n"], "e": keypair["e"]}, f)
    if use_keystore == "y":
        store_key_in_keystore(passphrase, key_name, keypair, keystore)
        print(f"RSA keys generated: {pubfile} (public), private stored in keystore")
    else:
        with open(privfile, "w") as f:
            json.dump(keypair, f)
        print(f"RSA keys generated: {pubfile} (public), {privfile} (private)")

def menu_encrypt_with_pub():
    pubfile = input("Recipient RSA public key file (default rsa_pub.json): ").strip() or "rsa_pub.json"
    if not os.path.exists(pubfile):
        print("Public key not found. Generate RSA keys first.")        
    inpath = input("Optional input file path (blank = prompt): ").strip() or None
    mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "t"
    n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
    rounds = int(input("Number of rounds (default 3): ").strip() or 3)
    layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
    shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    seed_len = int(input("Seed length (default 32): ").strip() or 32)
    nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
    nonce = b64decode(nonce_str) if nonce_str else None
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
    message = None
    numbers = None
    if inpath is None:
        if mode == "t":
            message = input("Message to encrypt: ")
        else:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
    encrypt_with_pub(pubfile, message=message, numbers=numbers, in_path=inpath, mode=mode, vp=vp, seed_len=seed_len, nonce=nonce)

def menu_decrypt_with_priv():
    use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() or "y"
    privfile, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Key name in keystore: ")
    else:
        privfile = input("RSA private key file (default rsa_priv.json): ").strip() or "rsa_priv.json"
    encfile = input("Encrypted file to decrypt (default enc_pub.json): ").strip() or "enc_pub.json"
    validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
    if not os.path.exists(encfile):
        print("Encrypted file not found.")
    decrypt_with_priv(keystore, privfile, encfile, passphrase, key_name, validity_window)

def menu_homomorphic_add_files():
    f1 = input("Encrypted file 1: ").strip()
    f2 = input("Encrypted file 2: ").strip()
    out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
    homomorphic_add_files(f1, f2, out)

def menu_homomorphic_mul_files():
    f1 = input("Encrypted file 1: ").strip()
    f2 = input("Encrypted file 2: ").strip()
    out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
    homomorphic_mul_files(f1, f2, out)

def menu_veinn_from_seed():
    use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() == "y"
    seed_input, keystore, passphrase, key_name = None, None, None, None
    if use_keystore:
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Seed name in keystore: ")
        seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
        seed_input = seed_data["seed"]
    else:
        seed_input = input("Enter seed string (publicly shared): ").strip()
    n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
    rounds = int(input("Number of rounds (default 3): ").strip() or 3)
    layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
    shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
    veinn_from_seed(seed_input, vp)

def menu_encrypt_with_public_veinn():
    use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() or "y"
    seed_input, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Seed name in keystore: ")                            
        store_key_in_keystore(passphrase, key_name, {"seed": key_name}, keystore)
        seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
        seed_input = seed_data["seed"]
    else:
        seed_input = input("Enter public seed string: ").strip()
    mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "t"
    message = None
    numbers = None
    bytes_per_number = None
    if mode == "t":
        message = input("Message to encrypt: ")
    else:
        content = input("Enter numbers (comma or whitespace separated): ").strip()
        raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
        numbers = [int(x) for x in raw_nums]
        bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
    n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
    rounds = int(input("Number of rounds (default 3): ").strip() or 3)
    layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
    shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    out_file = input("Output encrypted filename (default enc_pub_veinn.json): ").strip() or "enc_pub_veinn.json"
    nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
    nonce = b64decode(nonce_str) if nonce_str else None
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
    out_file = encrypt_with_public_veinn(seed_input, message, numbers, vp, out_file, mode, bytes_per_number, nonce)   

def menu_decrypt_with_public_veinn():
    use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() or "y"
    seed_input, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Seed name in keystore: ")
        seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
        seed_input = seed_data["seed"]
    else:
        seed_input = input("Enter public seed string: ").strip()
    enc_file = input("Encrypted file to decrypt (default enc_pub_veinn.json): ").strip() or "enc_pub_veinn.json"
    validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
    if not os.path.exists(enc_file):
        print("Encrypted file not found.")        
    decrypt_with_public_veinn(seed_input, enc_file, validity_window)

def main():
    parser = argparse.ArgumentParser(description="VEINN CLI with Lattice-based INN")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for homomorphic addition
    hom_add_parser = subparsers.add_parser("hom_add", help="Lattice-based homomorphic addition")
    hom_add_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_add_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_add_parser.add_argument("--out_file", default="hom_add.json", help="Output file")

    # Subparser for homomorphic multiplication
    hom_mul_parser = subparsers.add_parser("hom_mul", help="Lattice-based homomorphic multiplication")
    hom_mul_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_mul_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_mul_parser.add_argument("--out_file", default="hom_mul.json", help="Output file")

    # Subparser for creating keystore
    create_keystore_parser = subparsers.add_parser("create_keystore", help="Create encrypted keystore")
    create_keystore_parser.add_argument("--passphrase", required=True, help="Keystore passphrase")
    create_keystore_parser.add_argument("--keystore_file", default="keystore.json", help="Keystore filename")

    # Subparser for generating RSA keypair
    generate_rsa_parser = subparsers.add_parser("generate_rsa", help="Generate RSA keypair")
    generate_rsa_parser.add_argument("--bits", type=int, default=2048, help="RSA key size in bits")
    generate_rsa_parser.add_argument("--pubfile", default="rsa_pub.json", help="Public key filename")
    generate_rsa_parser.add_argument("--privfile", default="rsa_priv.json", help="Private key filename")
    generate_rsa_parser.add_argument("--keystore", help="Keystore filename for private key")
    generate_rsa_parser.add_argument("--passphrase", help="Keystore passphrase")
    generate_rsa_parser.add_argument("--key_name", help="Key name in keystore")

    # Subparser for public encryption
    public_encrypt_parser = subparsers.add_parser("public_encrypt", help="Encrypt with public key (RSA + VEINN)")
    public_encrypt_parser.add_argument("--pubfile", default="rsa_pub.json", help="RSA public key file")
    public_encrypt_parser.add_argument("--in_path", help="Input file path")
    public_encrypt_parser.add_argument("--mode", choices=["t", "n"], default="t", help="Input mode")
    public_encrypt_parser.add_argument("--n", type=int, default=8, help="Number of uint16 words per block")
    public_encrypt_parser.add_argument("--rounds", type=int, default=3, help="Number of rounds")
    public_encrypt_parser.add_argument("--layers_per_round", type=int, default=2, help="Layers per round")
    public_encrypt_parser.add_argument("--shuffle_stride", type=int, default=7, help="Shuffle stride")
    public_encrypt_parser.add_argument("--use_lwe", type=bool, default=True, help="Use LWE PRF")
    public_encrypt_parser.add_argument("--seed_len", type=int, default=32, help="Seed length")
    public_encrypt_parser.add_argument("--nonce", help="Custom nonce (base64)")
    public_encrypt_parser.add_argument("--out_file", default="enc_pub.json", help="Output encrypted file")

    # Subparser for decryption
    public_decrypt_parser = subparsers.add_parser("public_decrypt", help="Decrypt with private key")
    public_decrypt_parser.add_argument("--keystore", help="Keystore filename")
    public_decrypt_parser.add_argument("--privfile", default="rsa_priv.json", help="Private key file")
    public_decrypt_parser.add_argument("--encfile", default="enc_pub.json", help="Encrypted file")
    public_decrypt_parser.add_argument("--passphrase", help="Keystore passphrase")
    public_decrypt_parser.add_argument("--key_name", help="Key name in keystore")
    public_decrypt_parser.add_argument("--validity_window", type=int, default=3600, help="Timestamp validity window (seconds)")

    # Subparser for public VEINN derivation
    public_veinn_parser = subparsers.add_parser("public_veinn", help="Derive public VEINN from seed")
    public_veinn_parser.add_argument("--seed", required=True, help="Seed string")
    public_veinn_parser.add_argument("--n", type=int, default=8, help="Number of uint16 words per block")
    public_veinn_parser.add_argument("--rounds", type=int, default=3, help="Number of rounds")
    public_veinn_parser.add_argument("--layers_per_round", type=int, default=2, help="Layers per round")
    public_veinn_parser.add_argument("--shuffle_stride", type=int, default=7, help="Shuffle stride")
    public_veinn_parser.add_argument("--use_lwe", type=bool, default=True, help="Use LWE PRF")

    args = parser.parse_known_args()[0]

    try:
        match args.command:
            case "hom_add":
                homomorphic_add_files(args.file1, args.file2, args.out_file)        
            case "hom_mul":
                homomorphic_mul_files(args.file1, args.file2, args.out_file)
            case "create_keystore":
                create_keystore(args.passphrase, args.keystore_file)
                print(f"Keystore created: {args.keystore_file}")
            case "generate_rsa":
                keypair = generate_rsa_keypair(args.bits)
                with open(args.pubfile, "w") as f:
                    json.dump({"n": keypair["n"], "e": keypair["e"]}, f)
                if args.keystore and args.passphrase and args.key_name:
                    store_key_in_keystore(args.passphrase, args.key_name, keypair, args.keystore)
                    print(f"RSA keys generated: {args.pubfile} (public), private stored in keystore")
                else:
                    with open(args.privfile, "w") as f:
                        json.dump(keypair, f)
                    print(f"RSA keys generated: {args.pubfile} (public), {args.privfile} (private)")
            case "public_encrypt":
                vp = VeinnParams(
                    n=args.n,
                    rounds=args.rounds,
                    layers_per_round=args.layers_per_round,
                    shuffle_stride=args.shuffle_stride,
                    use_lwe=args.use_lwe
                )
                nonce = b64decode(args.nonce) if args.nonce else None
                encrypt_with_pub(
                    args.pubfile,
                    in_path=args.in_path,
                    mode=args.mode,
                    vp=vp,
                    seed_len=args.seed_len,
                    nonce=nonce,
                    out_file=args.out_file
                )
            case "public_decrypt":
                decrypt_with_priv(
                    args.keystore,
                    args.privfile,
                    args.encfile,
                    args.passphrase,
                    args.key_name,
                    args.validity_window
                )
            case "public_veinn":
                vp = VeinnParams(
                    n=args.n,
                    rounds=args.rounds,
                    layers_per_round=args.layers_per_round,
                    shuffle_stride=args.shuffle_stride,
                    use_lwe=args.use_lwe
                )
                veinn_from_seed(args.seed, vp)
        _=os.system("cls") | os.system("clear")        
        while True:
            print(f"{bcolors.OKCYAN}VEINN CLI — Lattice-based INN with LWE-based Key Nonlinearity{bcolors.ENDC}")
            print(f"{bcolors.OKCYAN}Nonlinearity via LWE PRF; linear INN for invertibility and homomorphism.{bcolors.ENDC}")
            print("")
            print(f"{bcolors.BOLD}1){bcolors.ENDC} Create encrypted keystore")
            print(f"{bcolors.BOLD}2){bcolors.ENDC} Generate RSA keypair (public/private)")
            print(f"{bcolors.BOLD}3){bcolors.ENDC} Encrypt with recipient public key (RSA + VEINN)")
            print(f"{bcolors.BOLD}4){bcolors.ENDC} Decrypt with private key")
            print(f"{bcolors.BOLD}5){bcolors.ENDC} Encrypt deterministically using public VEINN")
            print(f"{bcolors.BOLD}6){bcolors.ENDC} Decrypt deterministically using public VEINN")
            print(f"{bcolors.GREY}7) Lattice-based homomorphic add (file1, file2 -> out){bcolors.ENDC}")
            print(f"{bcolors.GREY}8) Lattice-based homomorphic multiply (file1, file2 -> out){bcolors.ENDC}")
            print(f"{bcolors.GREY}9) Derive public VEINN from seed{bcolors.ENDC}")

            print(f"{bcolors.BOLD}0){bcolors.ENDC} Exit")
            choice = input(f"{bcolors.BOLD}Choice: {bcolors.ENDC}").strip()

            try:
                match choice:
                    case "0":
                        break
                    case "1":
                        menu_generate_keystore()
                    case "2":
                        menu_generate_rsa_keypair()
                    case "3":
                        menu_encrypt_with_pub()
                    case "4":
                        menu_decrypt_with_priv()
                    case "5":
                        menu_encrypt_with_public_veinn()
                    case "6":
                        menu_decrypt_with_public_veinn()
                    case "7":
                        menu_veinn_from_seed()
                    case "8":
                        menu_homomorphic_add_files()
                    case "9":
                        menu_homomorphic_mul_files()
                    case _:
                        print("Invalid choice")
            except Exception as e:
                print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC}", e)
            _=input(f"{bcolors.OKGREEN}Any Key to Continue{bcolors.ENDC}")
            _=os.system("cls") | os.system("clear")
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC}", e)
        sys.exit(1)
if __name__ == "__main__":
    main()
