# Schnorr_secp256k1

Schnorr Signatures for secp256k1 in Java. 
A simple Java implementation (no external libs) of Sipa's Python reference implementation test vectors for BIP340 Schnorr signatures over secp256k1，and implements the nonceRFC6979 algorithm for randomly generating the determinant k when signing without the aux parameter.
BIP340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
