from dataclasses import dataclass
import numpy as np

# -----------------------------
# CLI Colors
# -----------------------------
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    GREY = '\033[90m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

Q = 2 ** 16  # modulus
DTYPE = np.uint16

@dataclass
class VeinnParams:
    n: int = 8  # uint16 words per block
    rounds: int = 3
    layers_per_round: int = 2
    shuffle_stride: int = 7
    use_lwe: bool = True
