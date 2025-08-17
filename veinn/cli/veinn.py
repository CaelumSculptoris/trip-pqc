import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import json
import os

# -----------------------------
# CLI Colors
# -----------------------------
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# -----------------------------
# Vectorize / Devectorize
# -----------------------------
def vectorize_message(msg_str):
    return np.frombuffer(msg_str.encode("utf-8"), dtype=np.uint8)

def devectorize_message(vec):
    return vec.tobytes().decode("utf-8", errors="ignore")

# -----------------------------
# Feedforward NN (public key)
# -----------------------------
class PublicNN(nn.Module):
    def __init__(self, input_dim, hidden_dim=128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid()  # outputs 0..1
        )

    def forward(self, x, training=False):
        y = self.net(x)
        if training:
            return y  # keep float for gradients
        return (y * 255.0).round().to(torch.uint8)  # cast only at encryption time

# -----------------------------
# Keystream generation per block
# -----------------------------
def generate_keystream(nn_model, private_key, session_blocks, device):
    keystream_blocks = []

    for block in session_blocks:
        combined = np.concatenate([private_key, block])
        x = torch.from_numpy(combined).float().unsqueeze(0).to(device)
        ks_block = nn_model(x, training=False).squeeze(0).cpu().numpy().astype(np.uint8)
        keystream_blocks.append(ks_block)

    return np.concatenate(keystream_blocks)

# -----------------------------
# XOR encrypt/decrypt
# -----------------------------
def xor_encrypt_decrypt(message_vec, keystream):
    repeat_times = (len(message_vec) + len(keystream) - 1) // len(keystream)
    ks_long = np.tile(keystream, repeat_times)[:len(message_vec)]
    return np.bitwise_xor(message_vec, ks_long)

# -----------------------------
# Split message into blocks
# -----------------------------
def split_into_blocks(vec, block_size):
    blocks = []
    for i in range(0, len(vec), block_size):
        block = vec[i:i+block_size]
        if len(block) < block_size:
            block = np.pad(block, (0, block_size - len(block)), 'constant')
        blocks.append(block)
    return blocks

# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    print(f"{bcolors.BOLD}Choose action:{bcolors.ENDC}")
    print(f"{bcolors.BOLD}1) Generate keys{bcolors.ENDC}")
    print(f"{bcolors.BOLD}2) Encrypt message{bcolors.ENDC}")
    print(f"{bcolors.BOLD}3) Decrypt message{bcolors.ENDC}")
    choice = input("Enter 1, 2, or 3: ").strip()

    BLOCK_SIZE = int(input("Block size in bytes (default 16): ") or 16)
    PRIVATE_KEY_SIZE = int(input("Private key length (default 16): ") or 16)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if choice == "1":
        # Generate random private key
        private_key = np.random.randint(0, 256, size=(PRIVATE_KEY_SIZE,), dtype=np.uint8)
        # Dummy session block for training NN
        session_dummy = np.zeros(BLOCK_SIZE, dtype=np.uint8)
        nn_model = PublicNN(input_dim=PRIVATE_KEY_SIZE+BLOCK_SIZE).to(device)
        optimizer = optim.Adam(nn_model.parameters(), lr=1e-2)

        # Train NN to reproduce input dummy (initialization / identity approximation)
        for epoch in range(100):
            optimizer.zero_grad()
            combined = np.concatenate([private_key, session_dummy])
            x = torch.from_numpy(combined).float().unsqueeze(0).to(device)  # leaf tensor
            output = nn_model(x, training=True)  # float output for gradients
            loss = ((output - x) ** 2).mean()
            loss.backward()
            optimizer.step()
            if (epoch+1) % 20 == 0:
                print(f"Epoch {epoch+1}, loss {loss.item():.4f}")

        filename = input("Save key JSON file (default keys.json): ") or "keys.json"
        data = {
            "private_key": private_key.tolist(),
            "public_nn": {k: v.detach().cpu().numpy().tolist() for k, v in nn_model.state_dict().items()}
        }
        with open(filename, "w") as f:
            json.dump(data, f)
        print(f"{bcolors.OKGREEN}Keys saved to {filename}{bcolors.ENDC}")

    elif choice == "2":
        key_file = input("Key JSON file: ") or "keys.json"
        if not os.path.exists(key_file):
            print(f"{bcolors.FAIL}Key file not found{bcolors.ENDC}")
            exit(1)
        with open(key_file, "r") as f:
            data = json.load(f)
        private_key = np.array(data["private_key"], dtype=np.uint8)
        nn_state = {k: torch.tensor(v) for k, v in data["public_nn"].items()}
        nn_model = PublicNN(input_dim=len(private_key)+BLOCK_SIZE).to(device)
        nn_model.load_state_dict(nn_state)

        msg = input("Message to encrypt: ")
        message_vec = vectorize_message(msg)
        session_blocks = split_into_blocks(message_vec, BLOCK_SIZE)
        keystream = generate_keystream(nn_model, private_key, session_blocks, device)
        encrypted_vec = xor_encrypt_decrypt(message_vec, keystream)

        out_file = input("Encrypted JSON filename (default encrypted.json): ") or "encrypted.json"
        out_data = {
            "encrypted": encrypted_vec.tolist(),
            "session_blocks": [b.tolist() for b in session_blocks],
            "public_nn": data["public_nn"]
        }
        with open(out_file, "w") as f:
            json.dump(out_data, f)
        print(f"{bcolors.OKGREEN}Encrypted message saved to {out_file}{bcolors.ENDC}")

    elif choice == "3":
        key_file = input("Key JSON file: ") or "keys.json"
        enc_file = input("Encrypted JSON file: ") or "encrypted.json"
        if not os.path.exists(key_file) or not os.path.exists(enc_file):
            print(f"{bcolors.FAIL}Required files not found{bcolors.ENDC}")
            exit(1)

        with open(key_file, "r") as f:
            data = json.load(f)
        private_key = np.array(data["private_key"], dtype=np.uint8)

        with open(enc_file, "r") as f:
            enc_data = json.load(f)
        encrypted_vec = np.array(enc_data["encrypted"], dtype=np.uint8)
        session_blocks = [np.array(b, dtype=np.uint8) for b in enc_data["session_blocks"]]
        nn_state = {k: torch.tensor(v) for k, v in enc_data["public_nn"].items()}

        nn_model = PublicNN(input_dim=len(private_key)+BLOCK_SIZE).to(device)
        nn_model.load_state_dict(nn_state)

        keystream = generate_keystream(nn_model, private_key, session_blocks, device)
        decrypted_vec = xor_encrypt_decrypt(encrypted_vec, keystream)
        decrypted_msg = devectorize_message(decrypted_vec)
        print(f"{bcolors.OKCYAN}Decrypted message: {decrypted_msg}{bcolors.ENDC}")

    else:
        print(f"{bcolors.FAIL}Invalid choice{bcolors.ENDC}")
