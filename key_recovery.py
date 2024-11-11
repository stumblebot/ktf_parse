#!/usr/bin/env python3

import binascii
import argparse

class KettleTwoWayPasswordEncoder:
    """
    A class used to encode and decode passwords using a two-way encryption method.

    Methods
    -------
    recover_seed(plaintext, ciphertext)
        Recovers the seed value used in the encryption process by XORing the plaintext and ciphertext.
    """
    @staticmethod
    def recover_seed(plaintext, ciphertext):
        """
        Recovers the seed value used in the encryption process.

        Parameters
        ----------
        plaintext : str
            The original plaintext string.
        ciphertext : str
            The hexadecimal string representing the ciphertext.

        Returns
        -------
        int
            The recovered seed value as an integer.
        """
        bi_r0 = int(binascii.hexlify(plaintext.encode('utf-8')), 16)
        bi_r1 = int(ciphertext, 16)
        bi_confuse = bi_r0 ^ bi_r1
        return bi_confuse

def main():
    """
    Main function to recover the seed used for encryption.

    This function parses command-line arguments to get the plaintext and ciphertext,
    then uses the KettleTwoWayPasswordEncoder to recover the seed used for encryption.

    Args:
        --plaintext (-p): The plaintext (bi_r0).
        --ciphertext (-c): The ciphertext (bi_r1).

    Returns:
        None: Prints the recovered seed to the console.
    """
    parser = argparse.ArgumentParser(description='Recover the seed used for encryption.')
    parser.add_argument('--plaintext', '-p', required=True, help='The plaintext (bi_r0)')
    parser.add_argument('--ciphertext', '-c', required=True, help='The ciphertext (bi_r1)')
    args = parser.parse_args()

    plaintext = args.plaintext
    ciphertext = args.ciphertext

    recovered_seed = KettleTwoWayPasswordEncoder.recover_seed(plaintext, ciphertext)
    print(f"Recovered seed: {recovered_seed}")

if __name__ == "__main__":
    main()
