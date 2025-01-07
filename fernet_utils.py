import base64
import binascii
import hmac
import time
import os
import struct
from pyaes import AESModeOfOperationCBC, Encrypter, Decrypter

__all__ = [
    "InvalidSignature",
    "InvalidToken",
    "Fernet"
]
_MAX_CLOCK_SKEW = 60


class InvalidToken(Exception):
    pass


class InvalidSignature(Exception):
    pass


log = []

class Fernet:
    """
    Pure python Fernet module
    see https://github.com/fernet/spec/blob/master/Spec.md
    """
    def __init__(self, key):
        if not isinstance(key, bytes):
            self._log_error("init function - raise #1 - key must be bytes")
            raise TypeError("key must be bytes.")

        try:
            key = base64.urlsafe_b64decode(key)
        except Exception as e:
            self._log_error(f"init function - raise #2 - {str(e)}")
            raise ValueError("Invalid base64-encoded key.")

        if len(key) != 32:
            self._log_error("init function - raise #3 - Fernet key must be 32 url-safe base64-encoded bytes.")
            raise ValueError("Fernet key must be 32 url-safe base64-encoded bytes.")

        self._signing_key = key[:16]
        self._encryption_key = key[16:]

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        try:
            encrypter = Encrypter(AESModeOfOperationCBC(self._encryption_key, iv))
            ciphertext = encrypter.feed(data)
            ciphertext += encrypter.feed()
        except Exception as e:
            self._log_error(f"_encrypt_from_parts function - raise #1 - {str(e)}")
            raise

        basic_parts = (b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext)

        hmactext = hmac.new(self._signing_key, digestmod='sha256')
        hmactext.update(basic_parts)

        return base64.urlsafe_b64encode(basic_parts + hmactext.digest())

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            self._log_error("decrypt function - raise #1 - token must be bytes")
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error) as e:
            self._log_error(f"decrypt function - raise #2 - {str(e)}")
            raise InvalidToken("Invalid base64-encoded token.")

        if not data or data[0] != 0x80:
            self._log_error("decrypt function - raise #3 - Invalid token header")
            raise InvalidToken("Invalid token header.")

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error as e:
            self._log_error(f"decrypt function - raise #4 - {str(e)}")
            raise InvalidToken("Invalid token timestamp.")

        if ttl is not None:
            if timestamp + ttl < current_time:
                self._log_error("decrypt function - raise #5 - Token expired")
                raise InvalidToken("Token expired.")

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                self._log_error("decrypt function - raise #6 - Token from the future")
                raise InvalidToken("Token from the future.")

        hmactext = hmac.new(self._signing_key, digestmod='sha256')
        hmactext.update(data[:-32])
        if not hmac.compare_digest(hmactext.digest(), data[-32:]):
            self._log_error("decrypt function - raise #7 - HMAC check failed")
            raise InvalidToken("HMAC check failed.")

        iv = data[9:25]
        ciphertext = data[25:-32]
        try:
            decryptor = Decrypter(AESModeOfOperationCBC(self._encryption_key, iv))
            plaintext = decryptor.feed(ciphertext)
            plaintext += decryptor.feed()
        except ValueError as e:
            self._log_error(f"decrypt function - raise #8 - {str(e)}")
            raise InvalidToken("Decryption failed.")

        return plaintext

    @staticmethod
    def _log_error(error_message):
        """
        Log an error message if it's not already in the global log.
        """
        global log
        if error_message not in log:
            log.append(error_message)

def generate_fernet_key_from_password(password):
    """
    Convert a password of any length into a valid Fernet key.
    Uses padding or truncation to ensure 32 bytes before base64 encoding.
    """
    password_bytes = password.encode()

    # If password is too short, pad it with repeating pattern
    if len(password_bytes) < 32:
        # Calculate how many times to repeat the password
        multiplier = (32 // len(password_bytes)) + 1
        password_bytes = password_bytes * multiplier

    # Take exactly 32 bytes
    password_bytes = password_bytes[:32]

    return base64.urlsafe_b64encode(password_bytes)

def encrypt_message(encryption_key, message):
    """Encrypt a message using the given encryption key."""
    fernet_key = generate_fernet_key_from_password(encryption_key)
    fernet = Fernet(fernet_key)
    return (fernet.encrypt(message.encode())).decode()

def decrypt_message(encryption_key, encrypted_message):
    nl='''
'''
    """Decrypt a message using the given encryption key."""
    #global aes_key
    #aes_key = encryption_key+"__"+encrypted_message[:5]+"..."+encrypted_message[-5:]
    if 'str' in str(type(encrypted_message)):
        encrypted_message = encrypted_message.encode()
    try:
        #global log

        #log.append(f"Decrypting with key: {encryption_key}")
        #log.append((f"encrypted message: {encrypted_message}"))
        fernet_key = generate_fernet_key_from_password(encryption_key)
        #log.append((f"fernet key: {fernet_key}"))
        fernet = Fernet(fernet_key)
        #log.append(f"fernet instance: {fernet}")
        decrypted_message = fernet.decrypt(encrypted_message)
        #log.append(f"decrypt message: {decrypted_message}")
        return decrypted_message.decode()
    except Exception as e:
        #return str(e)+nl+str(log)
        return "invalid key"
