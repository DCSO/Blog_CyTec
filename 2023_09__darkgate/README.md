# DCSO DarkGate tools

This project contains our tooling for DarkGate key log files.

See our accompanying [blog post](https://medium.com/@DCSO_CyTec) for more details.

The tooling consists of 3 separate tools:

- [Windows tool](darkgate_hwid.cpp) to fetch the necessary system specs to generate bot ID and AES key
- [Python3 script](darkgate_gen_hwid.py) to generate the bot ID and AES key
- [Windows tool written in Delphi](darkgate_decrypt_keylog.lpr) to decrypt log files

## Building ##

### darkgate\_hwid

- Download a suitable version of Visual Studio
- Create a new empty console project
- Import the source file
- Compile

### darkgate\_decrypt\_keylog

- Download latest [Lazarus IDE](https://www.lazarus-ide.org/)
- Download and install [dcpcrypt](https://sourceforge.net/projects/lazarus-ccr/files/DCPcrypt/DCPCrypt%202.0.4.2/)
- Open the .lpr file
- Compile
