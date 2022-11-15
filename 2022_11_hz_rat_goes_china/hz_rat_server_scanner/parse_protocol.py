# The parser is dirty and a result of a work in progress approach.
# Don't expect too much ;)


import dataclasses
import datetime

XOR_KEY = bytearray.fromhex("42")


@dataclasses.dataclass
class PKG:
    id: int
    payload_len: int = 0
    raw_payload: bytearray = b""
    next_payload_len: int = 0

    @property
    def payload(self):
        return _repeating_key_xor(self.raw_payload, XOR_KEY)

    def __str__(self):
        return f"[{self.id:03d}] {self.payload=}"


@dataclasses.dataclass
class INT_PKG:
    id: str
    payload_len: int = 0
    raw_payload: bytearray = b""
    next_payload_len: int = 0

    @property
    def payload(self):
        return self.raw_payload

    def __str__(self):
        return f"[{self.id:3}] {self.payload=}"


def main(client_hello: bytearray, communication: str):
    for msg in client_init_parser(client_hello):
        print(msg)

    for msg in parser(communication):
        print(msg)


def client_init_parser(client_hello: bytearray):
    assert len(client_hello) == 3
    yield _client_init_a_random_number(bytearray.fromhex(client_hello[0]))
    yield _client_init_b_hardcoded_strings(bytearray.fromhex(client_hello[1]))
    yield _client_init_c_unixtime(bytearray.fromhex(client_hello[2]))


def _client_init_a_random_number(data_bytes: bytearray) -> INT_PKG:
    assert len(data_bytes) == 4
    random_value = int.from_bytes(_repeating_key_xor(data_bytes, XOR_KEY), byteorder="big")
    return INT_PKG(id="INIT_A", raw_payload=f"client init a - {random_value=}".encode())


def _client_init_b_hardcoded_strings(data_bytes: bytearray) -> INT_PKG:
    assert len(data_bytes) == 5
    hardcoded_two = _repeating_key_xor(data_bytes, XOR_KEY)[0]
    hardcoded_unsigned_four = int.from_bytes(_repeating_key_xor(data_bytes[1:5], XOR_KEY), byteorder="big")

    assert hardcoded_two == 2
    assert hardcoded_unsigned_four == 4
    return INT_PKG(id="INIT_B", raw_payload=f"client init b - {hardcoded_two=} {hardcoded_unsigned_four=}".encode())


def _client_init_c_unixtime(data_bytes: bytearray) -> str:
    assert len(data_bytes) == 4
    tmp_timestamp = int.from_bytes(_repeating_key_xor(data_bytes, XOR_KEY), byteorder="little")
    unixtime = datetime.datetime.fromtimestamp(tmp_timestamp)
    return INT_PKG(id="INIT_C", raw_payload=f"client init c - {unixtime}".encode())


def parser(communication: str):
    iter_communication = iter(communication)
    for msg in iter_communication:
        yield from parse_communication_flow(bytearray.fromhex(msg), iter_communication)


def parse_communication_flow(data_bytes: bytearray, iter_communication):
    pkg_id = _get_pkg_id(data_bytes)
    pkg = PKG_MAPPER.get(pkg_id)(pkg_id, data_bytes)
    yield pkg
    if pkg.id == 1 and pkg.payload_len > 0 and len(pkg.raw_payload) == 0:
        yield PKG_MAPPER.get(-1)(-1, bytearray.fromhex(next(iter_communication)))


def _get_pkg_id(data: bytearray) -> bytes:
    return _repeating_key_xor(data, XOR_KEY)[0]


def __inner_container_pkg(pkg_id: int, bytes_data: bytearray) -> PKG:
    payload_len = int.from_bytes(_repeating_key_xor(bytes_data[0:4], XOR_KEY), byteorder="big")
    raw_payload = bytes_data[4:]
    return PKG(id=pkg_id, payload_len=payload_len, raw_payload=raw_payload)


def __outer_container_pkg(pkg_id: int, bytes_data: bytearray) -> PKG:
    # id = _get_pkg_id(bytes_data)
    payload_len = int.from_bytes(_repeating_key_xor(bytes_data[1:5], XOR_KEY), byteorder="big")
    raw_payload = bytes_data[5:]

    if len(raw_payload) > 0:
        raw_payload = raw_payload[4:]

    return PKG(id=pkg_id, payload_len=payload_len, raw_payload=raw_payload)


def __get_terminal_output(pkg_id: int, bytes_data: bytearray) -> PKG:
    # id = _get_pkg_id(bytes_data)
    payload_len = int.from_bytes(_repeating_key_xor(bytes_data[1:5], XOR_KEY), byteorder="big")
    return PKG(id=pkg_id, payload_len=payload_len, raw_payload=(bytes_data[5:]))


def __execute_shellcode(pkg_id: int, bytes_data: bytearray) -> PKG:
    # id = _get_pkg_id(bytes_data)
    payload_len = int.from_bytes(_repeating_key_xor(bytes_data[1:5], XOR_KEY), byteorder="big")
    return PKG(id=pkg_id, payload_len=payload_len, raw_payload=(bytes_data[5:]))


def __terminal_line_break(pkg_id: int, bytes_data: bytearray) -> PKG:
    # id = _get_pkg_id(bytes_data)
    payload_len = int.from_bytes(_repeating_key_xor(bytes_data[1:5], XOR_KEY), byteorder="big")
    return PKG(id=pkg_id, payload_len=payload_len, raw_payload=(bytes_data[5:]))


def __raise_unknown_command(pkg_id: int, bytes_data: bytearray):
    msg = f"__raise_unknown_command! {pkg_id=}"
    print(msg)
    msg += f"{bytes_data}"
    raise RuntimeError(msg)


def _repeating_key_xor(text: bytes, key: bytes) -> bytes:
    repetitions = 1 + (len(text) // len(key))
    key = key * repetitions
    key = key[:len(text)]

    # XOR text and key generated above and return the raw bytes
    return bytes([b ^ k for b, k in zip(text, key)])


PKG_MAPPER = {
    # Group - cmmands received but not found in sample (?)
    -1: __inner_container_pkg,
    0: __inner_container_pkg,
    1: __outer_container_pkg,

    # Group
    4: __raise_unknown_command,  # receive data and write to file
    # Group
    5: __get_terminal_output,  # read_file

    # Group
    3: __execute_shellcode,  # execute command
    8: __execute_shellcode,  # execute command
    9: __execute_shellcode,  # execute command

    # Group
    10: __raise_unknown_command,
    12: __raise_unknown_command,

    # Group
    11: __raise_unknown_command,  # could be ping

    # Group - cmmands received but not found in sample (?)
    100: __get_terminal_output,  # emt
    255: __terminal_line_break,  # command exit with error code
}
