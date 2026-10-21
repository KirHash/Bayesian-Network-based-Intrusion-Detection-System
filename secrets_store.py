"""
Encryption for secrets entered in the dashboard (webhook URLs, SMTP
passwords), so they are not readable in a copy of the database.

The key comes from IDS_SECRET_KEY, or is generated into a file next to the
database the first time it is needed. Whoever can read both the database
and that key file can read the secrets: this protects against a leaked
database or backup, not against someone with full access to the machine.
"""
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:"


class SecretBox:

    def __init__(self, key_path, env=os.environ):

        self.key_path = Path(key_path)

        self.env = env

        self.fernet = None

    def key(self):

        from_env = self.env.get("IDS_SECRET_KEY")

        if from_env:
            return from_env.encode()

        if self.key_path.exists():
            return self.key_path.read_bytes().strip()

        key = Fernet.generate_key()

        self.key_path.parent.mkdir(parents=True, exist_ok=True)

        # created readable by the owner only
        descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

        with os.fdopen(descriptor, "wb") as f:
            f.write(key)

        return key

    def box(self):

        if self.fernet is None:
            self.fernet = Fernet(self.key())

        return self.fernet

    def encrypt(self, text):

        return PREFIX + self.box().encrypt(text.encode()).decode()

    def decrypt(self, value):
        """Plain text for an encrypted value; anything else passes through."""

        if not (isinstance(value, str) and value.startswith(PREFIX)):
            return value

        try:
            return self.box().decrypt(value[len(PREFIX):].encode()).decode()
        except InvalidToken:
            raise ValueError(
                "a stored secret cannot be decrypted: the key changed or was lost"
            )

    @staticmethod
    def is_encrypted(value):

        return isinstance(value, str) and value.startswith(PREFIX)
