# Content

## Config extraction

We have written [a Python script](./get_config.py) to extract the embedded configuration found in unpacked Sauron Loader samples.

Example usage:

```py
$ python3 get_config.py sauron.unpacked.dll
{
  "magic": "0xbaadf00d",
  "flags": "0x40",
  "check_cis": false,
  "check_gov_domain": true,
  "header_dword_count": 3,
  "version_words": [
    1,
    0,
    0
  ],
  "additional_header_dwords": [],
  "rsa_private_key_len": 1192,
  "rsa_private_key_sha256": "6e4e2d528821025b082f6ebf429497f1df6ebf75c401e85a4637fa628d5854a0",
  "rsa_public_key_len": 294,
  "rsa_public_key_sha256": "7460272b6d4f0ca995783d1010952f0fa57ad7c877209947ae7ae1dc7d0a81ea",
  "group_id": "test_bot_group_uid",
  "build_id": "test_build_tag_uid",
  "c2_urls": [
    "...",
    "...",
    "...",
    "..."
  ]
}
```

## IoCs

We have provided related indicators of compromise in a [MISP event](./misp.event.json)
