# veinn/params.py
from dataclasses import dataclass
import numpy as np

Q = 2 ** 16  # modulus
DTYPE = np.uint16

@dataclass
class VeinnParams:
    n: int = 8  # uint16 words per block
    rounds: int = 3
    layers_per_round: int = 2
    shuffle_stride: int = 7
    use_lwe: bool = True
