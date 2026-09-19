                                      🛡️ ITShield-Floss

                         Advanced String Extraction & Malware Analysis Tool

   A powerful, single-file, GUI + CLI tool for extracting static, stack,and decoded/obfuscated strings from binary files 


This project is inspired by and builds upon the ideas of FLARE-FLOSS by Mandiant (Google).

    1-  Confidence scoring for every string (multi-word text bonus, English-frequency check)
    2 -  Packer detection (UPX, Themida, VMProtect, ASPack, …)
    3 -  Secret/IOC detection: AWS keys, GitHub tokens, private keys, crypto wallets…
    4 -  Hex context viewer — double-click any result
    5 -  YARA rule generation from high-confidence strings
    6 -  Session save/load (resume analysis later)
    7 -  Drag & drop, live search, sortable columns, type filter
    8 -  Clean light-theme GUI + full CLI with --debug / --find
    9 -  Built-in self-test (--selftest)
    
 Usage

GUI : python ITShield-Floss.py

CLI : python ITShield-Floss.py sample [option]

Full option list : python ITShield-Floss.py --help

![alt text](https://github.com/akhzari-itshield/ITShield-Floss/blob/main/ITShield-Floss-Image.png?raw=true)
