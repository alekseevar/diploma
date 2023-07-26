import pandas as pd
import operator
import csv
import os
import contextlib
from typing import Dict, List, Any, Optional
from aes import AESCipher


def decrypt_file(filename: str, cryptor: AESCipher):
    with open(filename, "rb") as fr:
        data = cryptor.decrypt(fr.read())
    with open(filename, "wb") as fw:
        fw.write(data)


def encrypt_file(filename: str, cryptor: AESCipher):
    with open(filename, "rb") as fr:
        data = cryptor.encrypt(fr.read())
    with open(filename, "wb") as fw:
        fw.write(data)


@contextlib.contextmanager
def try_decrypt_and_encrypt_after(filename: str, cryptor: Optional[AESCipher]):
    try:
        if cryptor is not None:
            decrypt_file(filename, cryptor)
        yield
    finally:
        if cryptor is not None:
            encrypt_file(filename, cryptor)


class CsvHandler:
    def __init__(
        self,
        filename: str,
        fieldnames: Optional[List[str]] = None,
        sep: str = "\t",
        mode: str = "rw",
        cryptor: Optional[AESCipher] = None,
        old_cryptor: Optional[AESCipher] = None,
    ):
        if old_cryptor is not None and cryptor is not None and os.path.exists(filename):
            decrypt_file(filename, old_cryptor)
            encrypt_file(filename, cryptor)
        self._filename = filename
        self._fieldnames = fieldnames or []
        self._sep = sep
        self._cryptor = cryptor
        if mode != "r":
            self._create_file_and_write_header()

    @staticmethod
    def _count_escapes(reader):
        b = reader(1024 * 1024)
        while b:
            yield b.count(b"\n")
            b = reader(1024 * 1024)

    @staticmethod
    def _count_rows_in(filename: str) -> int:
        with open(filename, "rb") as fp:
            return sum(
                n_escapes for n_escapes in CsvHandler._count_escapes(fp.raw.read)
            )

    def count_rows_in_associated_file(self, use_crypt: bool = False):
        with try_decrypt_and_encrypt_after(
            self._filename, self._cryptor if use_crypt else None
        ):
            return self._count_rows_in(self._filename)

    def _create_file_and_write_header(self):
        if (
            os.path.exists(self._filename)
            and self.count_rows_in_associated_file(use_crypt=True) > 0
        ):
            return
        with open(self._filename, "w", newline="") as csvfile:
            csv.DictWriter(
                csvfile, delimiter=self._sep, fieldnames=self._fieldnames
            ).writeheader()
        if self._cryptor is not None:
            encrypt_file(self._filename, self._cryptor)

    def read(self, columns_to_read: Optional[List[str]] = None) -> pd.DataFrame:
        with try_decrypt_and_encrypt_after(self._filename, self._cryptor):
            data = (
                pd.DataFrame(columns=self._fieldnames, data={})
                if self.count_rows_in_associated_file() < 1
                else pd.read_csv(self._filename, sep=self._sep)
            )
        if columns_to_read:
            data = data[columns_to_read]
        return data

    def find_entry_by(
        self, col_name: str, col_value: Any, columns_to_read: Optional[List[str]] = None
    ) -> pd.DataFrame:
        data = self.read(columns_to_read)
        return data.loc[data[col_name] == col_value]

    def get_column_values(self, columns: Optional[List[str]]) -> List[Any]:
        data = list(self.read(columns).to_records(index=False))
        if columns and len(columns) == 1:
            return list(map(operator.itemgetter(0), data))
        return data

    def append(self, row: Dict):
        with try_decrypt_and_encrypt_after(self._filename, self._cryptor), open(
            self._filename, "a", newline=""
        ) as csvfile:
            writer = csv.DictWriter(
                csvfile, delimiter=self._sep, fieldnames=self._fieldnames
            )
            writer.writerow(row)
