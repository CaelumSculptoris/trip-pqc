from ksnvt import vectorize_message, devectorize_message, encrypt, decrypt, bcolors, load_encrypted

def test_file(filename, layers=10):
    encrypted_vec, key = load_encrypted(filename)

    messages_to_test = [
        "Hello PQC world!",
        "🚀 Unicode test 🌟",
        "Null byte test: \x00\x01\x02"
    ]

    for msg in messages_to_test:
        print(f"{bcolors.OKBLUE}Testing message: {msg}{bcolors.ENDC}")
        vec = vectorize_message(msg)
        enc_vec = encrypt(vec, key, layers=layers)
        dec_vec = decrypt(enc_vec, key, layers=layers)
        dec_msg = devectorize_message(dec_vec)

        if dec_msg == msg:
            print(f"{bcolors.OKGREEN}Success!{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}Failure!{bcolors.ENDC}")
            print(f"Expected: {msg}")
            print(f"Got     : {dec_msg}")
        print("-"*50)

if __name__ == "__main__":
    filename = input("Enter encrypted vector file to test: ")
    test_file(filename)
