import pefile
from Crypto.Cipher import ChaCha20
from hashlib import sha512
import mmh3
import argparse
from pathlib import Path


def main(opts):
    PE_FILE = pefile.PE(opts.binary)

    for section in PE_FILE.sections:
        raw_data = section.get_data()

        murmurhash = int.from_bytes(raw_data[:4], "little")
        data_len = int.from_bytes(raw_data[4:8], "little")

        try:
            data = raw_data[8:data_len+8]
            new_key = sha512(opts.key.encode()).digest()[:56]
            cipher_obj = ChaCha20.new(key=new_key[:32], nonce=new_key[32:])
            plaintext = cipher_obj.decrypt(data)

            assert mmh3.hash(plaintext, seed= 0xffffffff, signed=False) == murmurhash
            print("Found Config in Section:", section.Name.replace(b"\x00", b"").decode())
            print("Key (len = 32):", plaintext[:32])
            print("Parsing Config...")
            parts = plaintext[32:].split(b"\x00\x00")
            parts = [part.replace(b"\x00", b"") for part in parts]

            print("[+] Default Mutex:", parts[0].decode())
            print("[+] Ransom extension and readme file:", parts[1].decode(), parts[2].decode())

            ext_end = parts[3][0] + 3
            extensions = parts[3:ext_end]
            print(f"[+] Ignored File Extensions: {b', '.join(extensions).decode()[1:]}")

            files_end = parts[ext_end][0] + ext_end
            files = parts[ext_end:files_end]
            print(f"[+] Ignored Files: {b', '.join(files).decode()[1:]}")

            files_end_2 = parts[files_end][0] + files_end
            files_2 = parts[files_end:files_end_2]
            print(f"[+] Ignored Directories: {b', '.join(files_2).decode()[1:]}")

            processes_end = parts[files_end_2][0] + files_end_2
            processes = parts[files_end_2:processes_end]
            print(f"[+] Killed Processes: {b', '.join(processes).decode()[1:]}")

            services_end = parts[processes_end][0] + processes_end
            services = parts[processes_end:services_end]
            print(f"[+] Killed Services: {b', '.join(services).decode()[1:]}")

            print(f"[+] Ransom Note:\n{b' '.join(parts[services_end:]).decode()}")
            return

        except:
            pass

    print("[-] Found no match. Please check binary and key!")
    return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary', type=Path, help="Path to SafePay binary", required=True)
    parser.add_argument('-k', '--key', type=str, help="the PASS key for the SafePay", required=True)
    return  parser.parse_args()

if __name__ == "__main__":
    opts = parse_args()
    main(opts)

