# ChaCha20-cs
Toy implementation of AEAD_ChaCha20_Poly1305 - do not use for real crypto.

The tag verification should be in constant time, however some operations, such as the Poly1305 key derivation could be vulnerable
to timing attacks.
