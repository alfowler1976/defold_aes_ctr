A defold extension that takes a lua string and applies AES-CTR function to it.

It uses the tiny-AES implementation from <https://github.com/kokke/tiny-AES-c/tree/master>

** Please read the installation and important note pages before using. **

# Installation

See [Installation](https://github.com/alfowler1976/defold_aes_ctr/wiki/Installation)

# API Reference

see [API Reference](https://github.com/alfowler1976/defold_aes_ctr/wiki/API-Reference)

# Important Notes

see [Important Notes](https://github.com/alfowler1976/defold_aes_ctr/wiki/Important-notes)

## New settings for v0.9.1.

This introduces two new functions:
* [aes_ctr.encrypt_using_seed_v2](https://github.com/alfowler1976/defold_aes_ctr/wiki/API-Reference#aes_ctrencrypt_using_seed_v2data-seed)
* [aes_ctr.decrypt_using_seed_v2](https://github.com/alfowler1976/defold_aes_ctr/wiki/API-Reference#aes_ctrdecrypt_using_seed_v2data-seed)

These use settings from the game project settings to help generate a key.  This provides a little more customisation. 
