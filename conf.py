from enum import Enum

class GPOTypes(str, Enum):
    user = "user"
    computer = "computer"

class SMBModes(str, Enum):
    embedded = "embedded"
    forwarded = "forwarded"
    none = "none"

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



OUTPUT_DIR = "GPT_out"
CLEAN_FILE = "to_clean.txt"
CLEAN_DIR = "cleaning"