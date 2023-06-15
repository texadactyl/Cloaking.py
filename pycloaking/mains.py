"""
Executable main programs for pycloaking
"""

import os.path
import sys
from argparse import ArgumentParser
from .cloaklib import cloak_file, uncloak_file

def oops(text):
    print("\n*** Oops, {text}\n")
    sys.exit(1)

def main_cloak(args=None):
    """
    This is the main entry-point for cloaking.

    Parameters
    ----------
    args : dict

    """
    # Create an option parser to get command-line input/arguments
    ap = ArgumentParser(description="Pythonic cloaking")
    ap.add_argument("-p", "--password", type=str, required=True,
                   help="Password to use in constructing the secret key")
    ap.add_argument("-i", "--infile", type=str, required=True,
                   help="Input cleartext file to be encrypted")
    ap.add_argument("-o", "--outfile", type=str, required=True,
                   help="Output file to contain the encrypted data")

    if args is None:
        args = ap.parse_args()
    else:
        args = ap.parse_args(args)

    if not os.path.isfile(args.infile):
        oops(f"main_cloak: Input file {args.infile} not found")

    et = cloak_file(args.password, args.infile, args.outfile)
    print(f"main_cloak: Cloaking elapsed time = {et} seconds")

def main_uncloak(args=None):
    """
    This is the main entry-point for uncloaking.

    Parameters
    ----------
    args : dict

    """
    # Create an option parser to get command-line input/arguments
    ap = ArgumentParser(description="Pythonic cloaking")
    ap.add_argument("-p", "--password", type=str, required=True,
                   help="Password to use in constructing the secret key")
    ap.add_argument("-i", "--infile", type=str, required=True,
                   help="Input ciphertext file to be decrypted")
    ap.add_argument("-o", "--outfile", type=str, required=True,
                   help="Output file to contain the cleartext data")

    if args is None:
        args = ap.parse_args()
    else:
        args = ap.parse_args(args)

    if not os.path.isfile(args.infile):
        oops(f"main_uncloak: Input file {args.infile} not found")

    et = uncloak_file(args.password, args.infile, args.outfile)
    print(f"main_uncloak: Uncloaking elapsed time = {et} seconds")
