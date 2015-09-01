# Curve25519+AES(CBC)
A simple program to test an idea I had, probably terrible. I'll port this to Orthros eventually.

It's simple, two Curve25519 public keys are computed from 32 bytes of random data - one for Bob, one for Alice. Public keys are shared between Bob and Alice and a shared key may be computed between them, SHA256 hash this key and use it as the AES key.

It actually works, neat-o.
```
Haifischs-MacBook-Air:Curve25519+AES haifisch$ build/curve_aes 
-------------------------------------------------------------
Generating keys for Alice...
Private Key #1 = Amlxq/wEyX/5oe4sOUA0roEE9ANrZg8VLt2Jl3NmtmQ=
Unencoded size: 32	-	 Encoded size: 44
Public Key  #1 = VqtYLl9bfPnuhYs6O71gj25JIpAF7bz1Qb+6ns2FEQk=
Unencoded size: 32	-	 Encoded size: 44
-------------------------------------------------------------
Generating keys for Bob...
Private Key #2 = 4ksLsZeWFEOclltwv5DpAY8UhtMYgxvtypENhJ2SBsQ=
Unencoded size: 32	-	 Encoded size: 44
Public Key  #2 = EMbKk0U78S0FnV0G9Nym8riMz0uR6Sy4dZZFBW0NjnQ=
Unencoded size: 32	-	 Encoded size: 44
-------------------------------------------------------------
Hashed secret: 14111c3f12a64889fc03d4d5997449c801ea9a33ab02f4e3fe133d49bfc900fc
Hashed original message: 54686520717569636b2062726f776e20666f78206a756d7073206f7665722074
-------------------------------------------------------------
Encrypting message...
Hashed ciphertext: b785f74f784550f1b1431bc848670fa5df9e01bde629585ee5f5d6fa50e69e64
Hashed decrypted plaintext: 54686520717569636b2062726f776e20666f78206a756d7073206f7665722074
-------------------------------------------------------------
PASS: enc/dec passed
```
