# SafePay Scripts
This is a collection of scripts that were used to analyse the safepay ransomware sample.

## Stack strings debofuscator
The stack strings deobfuscator is a script written for Ghidra in python. The script relys on the new Ghidra feature called PYGhidra.

The script iterates through the whole binary and tries to identify obfuscated stack strings. after that the script simulates each snippet that it found and prints the result. 

The script can be ran in 2 differnet ways, either by using the Ghidra GUI or using pyghidra headless execution.

To run pyghidra in headless mode the following needs to be done:
* set the GHIDRA_INSTALL_DIR to the location of ghidra (default case):
    * `export GHIDRA_INSTALL_DIR=/snap/ghidra/29/ghidra_11.3.1_PUBLIC/`
* provide the following to pyghidra
    * the binary and the script
    * example: `pyghidra malware/malware.bin malware/stack_strings/script.py`

```
10001860: MOV dword ptr [EBP + -0x40],0x180e1f1b
DECODED OUTPUT: 'advapi32.dll'
----------
100018dd: MOV dword ptr [EBP + -0x4d],0xc4c3c7c7
DECODED OUTPUT: 'rstrtmgr.dll'
----------
1000194d: MOV dword ptr [EBP + -0x5a],0xacb1a5aa
DECODED OUTPUT: 'kernel32.dll'
----------
100019e3: MOV dword ptr [EBP + -0x12],0x1c4b4143
DECODED OUTPUT: 'ole32.dll'
----------
10001a4e: MOV dword ptr [EBP + -0x33],0xdcd4dac0
DECODED OUTPUT: 'shell32.dll'
----------
10001abd: MOV dword ptr [EBP + -0x1c],0xfaf3e0fb
DECODED OUTPUT: 'ntdll.dll'
----------
10001b41: MOV dword ptr [EBP + -0x8],0x3d60617d
DECODED OUTPUT: 'mpr.dll'
----------
10001bad: MOV dword ptr [EBP + -0x27],0x47514443
DECODED OUTPUT: 'user32.dll'
----------
10001daf: MOV dword ptr [EBP + -0x1a],0x137c113f
DECODED OUTPUT: '/n "/i:'
----------
10001e04: MOV dword ptr [EBP + -0xa],0x35143714
DECODED OUTPUT: '" '
----------
10001e5f: MOV dword ptr [EBP + -0x24],0xa5e5a7f3
DECODED OUTPUT: 'UAC [%s][%s]'
...
...
...
```
## SafePay config extractor
The SafePay config extractor script extracts the encrypted built-in configuration that guides the malwares behaviour - such as which files or directories to encrypt, which system locations to avoid, and what ransom message to display to the victim after execution.

To run the config extractor 2 paramerters need to be provided:
* the malware binary
* the PASS key
```
usage: safepay_config_extractor.py [-h] -b BINARY -k KEY

options:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Path to SafePay binary
  -k KEY, --key KEY     the PASS key for the SafePay binary
```
The script will look for the encrypted data and then tries to decrypt it. If the decryption was successful the script will print the content of the config:
```
Found Config in Section: .debug
Key (len = 32): REDACTED
Parsing Config...
[+] Default Mutex: Global\DB1D-19B4-5094-D570-9841-E4BC-8ABD-29AA-03BB-84AD-C61B-1355-4FF2-194B-96BD-7E49
[+] Ransom extension and readme file: .safepay readme_safepay.txt
[+] Ignored File Extensions: .safepay, .exe, .dll, .pdb, .386, .cmd, .ani, .adv, .ps1, .cab, .msi, .msp, .com, .nls, .ocx, .mpa, .cpl, .mod, .hta, .prf, .rtp, .rpd, .bin, .hlp, .shs, .drv, .wpx, .bat, .rom, .msc, .spl, .msu, .ics, .key, .lnk, .hlp, .sys, .drv, .cur, .idx, .ldf, .ini, .reg, .apk, .ttf, .otf, .fon, .fnt, .dmp, .tmp, .pif, .wav, .wma, .dmg, .app, .ipa, .xex, .wad, .msu, .icns, .theme, .diagcfg, .diagcab, .diagpkg, .msstyles, .gadget, .woff, .part, .sfcache, .winmd, .icl, .deskthemepack, .nomedia
[+] Ignored Files: readme_safepay.txt, autorun.inf, boot.ini, bootfont.bin, bootsect.bak, desktop.ini, iconcache.db, ntldr, ntuser.dat, ntuser.dat.log, ntuser.ini, thumbs.db
[+] Ignored Directories: $WinREAgent, $Windows.~bt, public, config.msi, intel, msocache, $recycle.bin, $windows.~ws, tor browser, boot, windows nt, msbuild, microsoft, all users, system volume information, perflogs, application data, windows, windows.old, appdata, common files, windows defender, windowsapp, windowspowershell, usoshared, windows security, program files, program files (x86), programdata, default, mozilla firefox
[+] Killed Processes: sql, oracle, ocssd, dbsnmp, synctime, agntsvc, isqlplussvc, xfssvccon, mydesktopservice, ocautoupds, encsvc, firefox, tbirdconfig, mydesktopqos, ocomm, dbeng50, sqbcoreservice, excel, infopath, msaccess, mspub, far, onenote, outlook, powerpnt, steam, thebat, thunderbird, visio, winword, wordpad, notepad, wuauclt, onedrive, sqlmangr
[+] Killed Services: vss, sql, svc$, memtas, mepocs, msexchange, sophos, veeam, backup, GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr
[+] Ransom Note: [...]
```

## SafePay decryption test tooling

In order to analyze the file encryption we wrote tooling to patch in an ECC key of our choice. You can find the code in [patch_key.py](https://github.com/DCSO/Blog_CyTec/blob/main/2025_05__safepay/patch_key.py) along with a pre-generated ECC key pair.

Files encrypted with this patched key can be decrypted (more or less likely) using the experimental script [decrypt_file.py](https://github.com/DCSO/Blog_CyTec/blob/main/2025_05__safepay/decrypt_file.py). It may not correctly implement the chunk stepping as it more served as a proof of concept for understanding the key material handling.
