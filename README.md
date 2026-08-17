A defold extension that takes a lua string and applies AES-CTR function to it.

It uses the tiny-AES implementation from <https://github.com/kokke/tiny-AES-c/tree/master>

# Installation

You can use this extension in your own project by adding this project as a [<u>Defold library dependency</u>](https://defold.com/manuals/libraries/#setting-up-library-dependencies).\
Open your `game.project` file, select `Project `and add a `Dependencies `field:

<u>https://github.com/alfowler1976/defold_aes_ctr/archive/refs/tags/v0.9.0.zip</u>

# **API Reference**


**aes_ctr.encrypt_using_key(data, key)**

Encrypts the data using an AES function. It generates an IV internally. The return is a string with the encrypted data, IV and checksum for tampering detection.
Parameters:

- data (string): The raw binary or text string to be encrypted
- key (table): A table of 32 integer numbers between 0-255. Throws an error table length is not 32 or it finds non numbers

Returns:

- (string): The binary string containing the IV, encrypted data and checksum
  

**aes_ctr.decrypt_using_key(data, key)**

decrypts data (previously encoded using aes_ctr.encrypt_using_key) and detects tampering. 
Parameters:

- data (string): The raw binary or text string to be encrypted/decrypted.
- key (table): A table of 32 integer numbers between 0-255. Throws an error table length is not 32 or it finds non numbers

Returns:

- (string): The binary string containing the IV, encrypted data and checksum. return nil if fails
- (string): error string (optional. only returns if fail)

**aes_ctr.encrypt_using_seed(data, seed)**

Encrypts the data using an AES function. It generates a key (derived from the seed) an IV internally. The return is a string with the encrypted data, IV and checksum for tampering detection.
This provides a little more protection against reverse engineering as the key is never revealed in lua

Parameters:

- data (string): The raw binary or text string to be encrypted
- seed (string): A string to act as a basis for a seed

Returns:

- (string): The binary string containing the IV, encrypted data and checksum
  

**aes_ctr.decrypt_using_seed(data, seed)**

decrypts data (previously encoded using aes_ctr.encrypt_using_seed) and detects tampering. 
This provides a little more protection against reverse engineering as the key is never revealed in lua

Parameters:

- data (string): The raw binary or text string to be encrypted/decrypted.
- seed (string): A string to act as a basis for a seed

Returns:

- (string): The binary string containing the IV, encrypted data and checksum. return nil if fails
- (string): error string (optional. only returns if fail)

 # Important Notes

Client-Side Security: LuaJIT is relatively easy to decompile, so storing keys directly in client-side code will make them easy to extract. The seed-based variants offer more protection because the key is generated internally—meaning it never appears in Lua. Even if an attacker discovers the seed, they would have to decompile and reverse-engineer the C++ code to obtain the key, which is significantly harder.

Customization: If you want even more protection, you can download the code and include it directly in your project rather than using it as a remote dependency. This allows you to customize internal elements, such as modifying the generate_key_from_seed function to create a completely unique implementation.

Testing & Data Backups (Disclaimer): While this extension works perfectly well for my own project, it has not been exhaustively tested across every possible situation or environment. Always keep a backup of your raw, unencrypted data before running it through encryption functions, just in case you run into any unexpected issues
