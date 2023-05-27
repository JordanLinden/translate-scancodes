#!/usr/bin/env python3

"""Translate key scancodes in hexdumps captured from decrypted RDP traffic to human-readable characters.
    
    This script is meant to intake Wireshark tcp stream hexdumps from decrypted RDP session captures.
    Its functionality will break if it parses a different format.
    Please note that this is an incomplete implementation that does not cover all keystroke combinations.
    
    This script was inspired by the post "Retrospective Decryption of SSL-encrypted RDP Sessions" from Portcullis Labs.
    View the post here:
        https://labs.portcullis.co.uk/blog/retrospective-decryption-of-ssl-encrypted-rdp-sessions/
    
    Key scan codes were referenced from the following Microsoft docs page:
        https://learn.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa299374(v=vs.60)
"""


import argparse
import re
from contextlib import closing


__author__ = "Jordan Linden"
__version__ = "1.0"
__status__ = "Prototype"


SCANCODES = {
    "1E": ("a","A"),
    "30": ("b","B"),
    "2E": ("c","C"),
    "20": ("d","D"),
    "12": ("e","E"),
    "21": ("f","F"),
    "22": ("g","G"),
    "23": ("h","H"),
    "17": ("i","I"),
    "24": ("j","J"),
    "25": ("k","K"),
    "26": ("l","L"),
    "32": ("m","M"),
    "31": ("n","N"),
    "18": ("o","O"),
    "19": ("p","P"),
    "10": ("q","Q"),
    "13": ("r","R"),
    "1F": ("s","S"),
    "14": ("t","T"),
    "16": ("u","U"),
    "2F": ("v","V"),
    "11": ("w","W"),
    "2D": ("x","X"),
    "15": ("y","Y"),
    "2C": ("z","Z"),
    "0B": ("0",")"),
    "02": ("1","!"),
    "03": ("2","@"),
    "04": ("3","#"),
    "05": ("4","$"),
    "06": ("5","%"),
    "07": ("6","^"),
    "08": ("7","&"),
    "09": ("8","*"),
    "0A": ("9","("),
    "29": ("`","~"),
    "0C": ("-","_"),
    "0D": ("=","+"),
    "2B": ("\\","|"),
    "1A": ("[","{"),
    "1B": ("]","}"),
    "27": (";",":"),
    "28": ("'","\""),
    "33": (",","<"),
    "34": (".",">"),
    "35": ("/","?"),
    "39": (" ",),
    "3A": ("CAPS",),
    "2A": ("LSHFT",),
    "36": ("RSHFT",),
    "1D": ("CTRL",),
    "1C": ("\n",),
    "0E": ("BKSP",),
    "53": ("DEL",),
    "01": ("ESC",)
}

KEYS_SHIFT = ("LSHFT", "RSHFT")
KEYS_CAPS = ("CAPS",)


def convert(file):
    char_arr = []
    
    pattern = re.compile('44 04 0[01] [0-9a-fA-F]{2}')
    
    caps_pressed = False
    shift_pressed = False
    
    for line in file:
        match_obj = pattern.search(line)
        
        if match_obj is None:
            continue
        
        line_arr = match_obj.group(0).split(' ')
        
        char_tup = SCANCODES.get(line_arr[3].upper())
        
        if char_tup is None:
            print("Unknown character found: ",line_arr[3])
        else:
            if line_arr[2] == "00":
                if char_tup[0] in KEYS_CAPS:
                    caps_pressed = not caps_pressed
                    continue
                if char_tup[0] in KEYS_SHIFT:
                    shift_pressed = True
                    continue
                
                switch_alt = ((shift_pressed and not caps_pressed) or (caps_pressed and not shift_pressed))
                
                try:
                    char_arr.append(char_tup[1 if switch_alt else 0])
                except IndexError:
                    char_arr.append(char_tup[0])
            elif line_arr[2] == "01":
                if char_tup[0] in KEYS_SHIFT:
                    shift_pressed = False
    
    return ''.join(char_arr)


def main():
    parser = argparse.ArgumentParser(
        prog='translate-scancodes.py',
        description=__doc__
    )
    
    parser.add_argument("file", type=argparse.FileType("r"), help='specify a hexdump file to parse')
    parser.add_argument("-v", "--version", action="version", version='%(prog)s ' + __version__)
    
    args = parser.parse_args()
    
    file = args.file
    
    with closing(file):
        result = convert(file)
    
    print(result)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
