# veinn/cli.py
import os
import sys
import json
import argparse
from base64 import b64decode
from params import VeinnParams
from keystore import create_keystore, store_key_in_keystore, retrieve_key_from_keystore
from rsa_oaep import generate_rsa_keypair
from public_api import (
    encrypt_with_pub, decrypt_with_priv,
    veinn_from_seed, encrypt_with_public_veinn, decrypt_with_public_veinn,
)
from homomorphic import homomorphic_add_files, homomorphic_mul_files

def main():
    parser = argparse.ArgumentParser(description="VEINN CLI with Lattice-based INN")
    subparsers = parser.add_subparsers(dest="command")

    hom_add_parser = subparsers.add_parser("hom_add", help="Lattice-based homomorphic addition")
    hom_add_parser.add_argument("--file1", required=True)
    hom_add_parser.add_argument("--file2", required=True)
    hom_add_parser.add_argument("--out_file", default="hom_add.json")

    hom_mul_parser = subparsers.add_parser("hom_mul", help="Lattice-based homomorphic multiplication")
    hom_mul_parser.add_argument("--file1", required=True)
    hom_mul_parser.add_argument("--file2", required=True)
    hom_mul_parser.add_argument("--out_file", default="hom_mul.json")

    create_keystore_parser = subparsers.add_parser("create_keystore", help="Create encrypted keystore")
    create_keystore_parser.add_argument("--passphrase", required=True)
    create_keystore_parser.add_argument("--keystore_file", default="keystore.json")

    generate_rsa_parser = subparsers.add_parser("generate_rsa", help="Generate RSA keypair")
    generate_rsa_parser.add_argument("--bits", type=int, default=2048)
    generate_rsa_parser.add_argument("--pubfile", default="rsa_pub.json")
    generate_rsa_parser.add_argument("--privfile", default="rsa_priv.json")
    generate_rsa_parser.add_argument("--keystore")
    generate_rsa_parser.add_argument("--passphrase")
    generate_rsa_parser.add_argument("--key_name")

    public_encrypt_parser = subparsers.add_parser("public_encrypt", help="Encrypt with public key (RSA + VEINN)")
    public_encrypt_parser.add_argument("--pubfile", default="rsa_pub.json")
    public_encrypt_parser.add_argument("--in_path")
    public_encrypt_parser.add_argument("--mode", choices=["text", "numeric"], default="text")
    public_encrypt_parser.add_argument("--n", type=int, default=8)
    public_encrypt_parser.add_argument("--rounds", type=int, default=3)
    public_encrypt_parser.add_argument("--layers_per_round", type=int, default=2)
    public_encrypt_parser.add_argument("--shuffle_stride", type=int, default=7)
    public_encrypt_parser.add_argument("--use_lwe", type=bool, default=True)
    public_encrypt_parser.add_argument("--seed_len", type=int, default=32)
    public_encrypt_parser.add_argument("--nonce")
    public_encrypt_parser.add_argument("--out_file", default="enc_pub.json")

    public_decrypt_parser = subparsers.add_parser("public_decrypt", help="Decrypt with private key")
    public_decrypt_parser.add_argument("--keystore")
    public_decrypt_parser.add_argument("--privfile", default="rsa_priv.json")
    public_decrypt_parser.add_argument("--encfile", default="enc_pub.json")
    public_decrypt_parser.add_argument("--passphrase")
    public_decrypt_parser.add_argument("--key_name")
    public_decrypt_parser.add_argument("--validity_window", type=int, default=3600)

    public_veinn_parser = subparsers.add_parser("public_veinn", help="Derive public VEINN from seed")
    public_veinn_parser.add_argument("--seed", required=True)
    public_veinn_parser.add_argument("--n", type=int, default=8)
    public_veinn_parser.add_argument("--rounds", type=int, default=3)
    public_veinn_parser.add_argument("--layers_per_round", type=int, default=2)
    public_veinn_parser.add_argument("--shuffle_stride", type=int, default=7)
    public_veinn_parser.add_argument("--use_lwe", type=bool, default=True)

    args = parser.parse_known_args()[0]

    try:
        if args.command == "hom_add":
            homomorphic_add_files(args.file1, args.file2, args.out_file)

        elif args.command == "hom_mul":
            homomorphic_mul_files(args.file1, args.file2, args.out_file)

        elif args.command == "create_keystore":
            create_keystore(args.passphrase, args.keystore_file)
            print(f"Keystore created: {args.keystore_file}")

        elif args.command == "generate_rsa":
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

        elif args.command == "public_encrypt":
            vp = VeinnParams(
                n=args.n, rounds=args.rounds, layers_per_round=args.layers_per_round,
                shuffle_stride=args.shuffle_stride, use_lwe=args.use_lwe
            )
            nonce = b64decode(args.nonce) if args.nonce else None
            encrypt_with_pub(
                args.pubfile, in_path=args.in_path, mode=args.mode, vp=vp,
                seed_len=args.seed_len, nonce=nonce, out_file=args.out_file
            )

        elif args.command == "public_decrypt":
            decrypt_with_priv(
                args.keystore, args.privfile, args.encfile,
                args.passphrase, args.key_name, args.validity_window
            )

        elif args.command == "public_veinn":
            vp = VeinnParams(
                n=args.n, rounds=args.rounds, layers_per_round=args.layers_per_round,
                shuffle_stride=args.shuffle_stride, use_lwe=args.use_lwe
            )
            veinn_from_seed(args.seed, vp)

        else:
            # Interactive menu preserved
            print("VEINN CLI — Lattice-based INN with LWE-based Key Nonlinearity")
            print("Nonlinearity via LWE PRF; linear INN for invertibility and homomorphism.")
            while True:
                print("")
                print("1) Create encrypted keystore")
                print("2) Generate RSA keypair (public/private)")
                print("3) Encrypt with recipient public key (RSA + VEINN)")
                print("4) Decrypt with private key")
                print("5) Lattice-based homomorphic add (file1, file2 -> out)")
                print("6) Lattice-based homomorphic multiply (file1, file2 -> out)")
                print("7) Derive public VEINN from seed")
                print("8) Encrypt deterministically using public VEINN")
                print("9) Decrypt deterministically using public VEINN")
                print("0) Exit")
                choice = input("Choice: ").strip()
                try:
                    if choice == "0":
                        break
                    elif choice == "1":
                        passphrase = input("Enter keystore passphrase: ")
                        keystore_file = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                        create_keystore(passphrase, keystore_file)
                        print(f"Keystore created: {keystore_file}")
                    elif choice == "2":
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
                    elif choice == "3":
                        pubfile = input("Recipient RSA public key file (default rsa_pub.json): ").strip() or "rsa_pub.json"
                        if not os.path.exists(pubfile):
                            print("Public key not found. Generate RSA keys first.")
                            continue
                        inpath = input("Optional input file path (blank = prompt): ").strip() or None
                        mode = (input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "text")
                        mode = "text" if mode == "t" else "numeric"
                        n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
                        rounds = int(input("Number of rounds (default 3): ").strip() or 3)
                        layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
                        shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
                        use_lwe = (input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y") == "y"
                        seed_len = int(input("Seed length (default 32): ").strip() or 32)
                        nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
                        nonce = b64decode(nonce_str) if nonce_str else None
                        vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
                        message, numbers = None, None
                        if inpath is None:
                            if mode == "text":
                                message = input("Message to encrypt: ")
                            else:
                                content = input("Enter numbers (comma/space separated): ").strip()
                                raw = [s for s in content.replace(",", " ").split() if s]
                                numbers = [int(x) for x in raw]
                        encrypt_with_pub(pubfile, message=message, numbers=numbers, in_path=inpath, mode=mode, vp=vp, seed_len=seed_len, nonce=nonce)
                    elif choice == "4":
                        use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() == "y"
                        privfile, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("RSA private key file (default rsa_priv.json): ").strip() or "rsa_priv.json"
                        encfile = input("Encrypted file to decrypt (default enc_pub.json): ").strip() or "enc_pub.json"
                        validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
                        if not os.path.exists(encfile):
                            print("Encrypted file not found.")
                            continue
                        decrypt_with_priv(keystore, privfile, encfile, passphrase, key_name, validity_window)
                    elif choice == "5":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
                        homomorphic_add_files(f1, f2, out)
                    elif choice == "6":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
                        homomorphic_mul_files(f1, f2, out)
                    elif choice == "7":
                        seed_input = input("Enter seed string (publicly shared): ").strip()
                        n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
                        rounds = int(input("Number of rounds (default 3): ").strip() or 3)
                        layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
                        shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
                        use_lwe = (input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y") == "y"
                        vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
                        veinn_from_seed(seed_input, vp)
                    elif choice == "8":
                        seed_input = input("Enter public seed string: ").strip()
                        mode = (input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "t")
                        mode = "text" if mode == "t" else "numeric"
                        message, numbers, bpn = None, None, None
                        if mode == "text":
                            message = input("Message to encrypt: ")
                        else:
                            content = input("Enter numbers (comma/space separated): ").strip()
                            raw = [s for s in content.replace(",", " ").split() if s]
                            numbers = [int(x) for x in raw]
                            bpn = int(input("Bytes per number (default 4): ").strip() or 4)
                        n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
                        rounds = int(input("Number of rounds (default 3): ").strip() or 3)
                        layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
                        shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
                        use_lwe = (input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y") == "y"
                        out_file = input("Output encrypted filename (default enc_pub_veinn.json): ").strip() or "enc_pub_veinn.json"
                        nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
                        nonce = b64decode(nonce_str) if nonce_str else None
                        vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
                        encrypt_with_public_veinn(seed_input, message, numbers, vp, out_file, mode, bpn, nonce)
                    elif choice == "9":
                        seed_input = input("Enter public seed string: ").strip()
                        enc_file = input("Encrypted file to decrypt (default enc_pub_veinn.json): ").strip() or "enc_pub_veinn.json"
                        validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
                        if not os.path.exists(enc_file):
                            print("Encrypted file not found.")
                            continue
                        decrypt_with_public_veinn(seed_input, enc_file, validity_window)
                    else:
                        print("Invalid choice")
                except Exception as e:
                    print("ERROR:", e)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
