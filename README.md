# Curve25519+AES(CBC)
A simple program to test an idea I had, probably terrible. I'll port this to Orthros eventually.

It's simple, two Curve25519 public keys are computed from 32 bytes of random data - one for Bob, one for Alice. Public keys are shared between Bob and Alice and a shared key may be computed between them, SHA256 hash this key and use it as the AES key.

It actually works, neat-o.
```
Haifischs-MacBook-Air:Curve25519+AES haifisch$ build/curve_aes
-------------------------------------------------------------
Generating keys for Alice...
Private Key #1 = E1wIqFgwlC5ChHTfSlDqte+X8OXhvYjbHOa7g1UAZCU=
Unencoded size: 32	-	 Encoded size: 44
Public Key  #1 = dfL7p66tu6cE9h2wuXhNTWjuqgf4Xkur113f3TBtnXo=
Unencoded size: 32	-	 Encoded size: 44
-------------------------------------------------------------
Generating keys for Bob...
Private Key #2 = E1wIqFgwlC5ChHTfSlDqte+X8OXhvYjbHOa7g1UAZCU=
Unencoded size: 32	-	 Encoded size: 44
Public Key  #2 = dfL7p66tu6cE9h2wuXhNTWjuqgf4Xkur113f3TBtnXo=
Unencoded size: 32	-	 Encoded size: 44
-------------------------------------------------------------
Hashed secret: 1a3af2df52b1cd2ce869502ef17c7c11c6cfee83c33d2c39aef9ba78e7409970
Hashed original message: 54686520717569636b2062726f776e20666f78206a756d7073206f7665722074
-------------------------------------------------------------
Encrypting message...
Hashed ciphertext: b785f74f784550f1b1431bc848670fa5df9e01bde629585ee5f5d6fa50e69e64
Hashed decrypted plaintext: 54686520717569636b2062726f776e20666f78206a756d7073206f7665722074
OK: enc/dec ok for "The quick brown fox jumps over the lazy dog"
```
