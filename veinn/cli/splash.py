import re
import sys

# ANSI color codes
grey = '\033[90m'
blue = '\033[34m'
cyan = '\033[36m'
green = '\033[32m'
white = '\033[37m'
reset = '\033[0m'

# Function to calculate visible length (ignoring ANSI codes)
def visible_len(s):
    return len(re.sub(r'\033\[\d+m', '', s))

# Logo ASCII art from the provided input 
logo_lines = [
    '',
    '',    
    f'                                 =--=.',
    f'                               :=-----=',
    f'               .-**=.        ...------:',
    f'              :=-----=.:::..:  .+----*',
    f'              :-------          :.::.',
    f'             .:=----+-         :   ..',
    f'          .::     :          ..     ..',
    f'  -=---==:.       ..        .:       ..',
    f' .=-----=.        .:       ::.        ..',
    f' .=-----=..       ..       :.       ..---.',
    f'   -+=+-.-.        .       -:      :=----=::',
    f'           .:      :      -       :--------:',
    f'             .:.   :     :         ::+----*:',
    f'                ::+=-+=...            ...',
    f'                :=-----=.',
    f'                :=-----=.',
    f'                 :==-+=.',
    '',
    ''
]

# Right side: VEINN and options list
right_lines = [
    f'{green}VEINN{reset}',
    f'{cyan}1){reset} {white}Train Model{reset}',
    f'{cyan}2){reset} {white}Encrypt Vector{reset}',
    f'{cyan}3){reset} {white}Invert Network{reset}',
    f'{cyan}4){reset} {white}Decrypt Data{reset}',
    f'{cyan}5){reset} {white}Evaluate Performance{reset}',
    f'{cyan}6){reset} {white}Load Dataset{reset}',
    f'{cyan}7){reset} {white}Save Model{reset}',
    f'{cyan}8){reset} {white}Visualize Network{reset}',
    f'{cyan}9){reset} {white}Exit{reset}'
]

# Determine the maximum visible width for the logo part
max_logo_width = max(visible_len(line) for line in logo_lines)

# Pad to align the right side
padding = max_logo_width + 4  # Add some space between logo and list

# Determine the number of lines to print
max_lines = max(len(logo_lines), len(right_lines))

# Print the splash screen
for i in range(max_lines):
    left = logo_lines[i] if i < len(logo_lines) else ''
    right = right_lines[i] if i < len(right_lines) else ''
    # Pad the left part
    left_padded = left + ' ' * (padding - visible_len(left))
    print(left_padded + right)