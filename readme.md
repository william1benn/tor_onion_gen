### Tor onion generator

_Generate tor url from tor specs_ 

[https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt](https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt)


_Torspec onion outline_
* The public key is the 32 bytes ed25519 master pubkey of the hidden service.
* The checksum is truncated to two bytes before inserting it in onion_address
* Current default byte value is '\x03' for checksum
* Configuration of onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
* Configuration of checksum = H(".onion checksum" | PUBKEY | VERSION)[:2]
* Private key expansion referenced from A.2. Tor's key derivation scheme bitwise operations