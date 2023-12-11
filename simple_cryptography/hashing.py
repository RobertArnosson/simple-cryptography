import base64
import hashlib
import argon2
import os
from .formats import to_bytes

@staticmethod
def sha1(message: str = None, path: str = None) -> str:
    """
    Generate the SHA-1 hash of either a provided message or the content of a file.\n
    **Do not use for passwords**

    Parameters:
    - message (str, optional): The input message to be hashed using SHA-1. Default is None.
    - path (str, optional): The path to the file whose content is to be hashed using SHA-1. Default is None.

    Returns:
    - str: If path is provided, returns the SHA-1 hash of the file content.\n
           If message is provided, returns the SHA-1 hash of the message.\n
           If neither path nor message is provided, returns a string indicating that no message or path was provided.\n
    """

    if path is not None:
        with open(path, 'rb') as f:
            hash_object = hashlib.new('sha1')

            while chunk := f.read(8192):
                hash_object.update(chunk)

        file_hash = hash_object.hexdigest()
        return file_hash

    if message is not None:
        return hashlib.sha1(to_bytes(message)).hexdigest()

    return "No message or path provided"


@staticmethod
def md5(message: str = None, path: str = None) -> str:
    """
    Generate the MD5 hash of either a provided message or the content of a file.\n
    **Do not use for passwords**

    Parameters:
    - message (str, optional): The input message to be hashed using MD5. Default is None.
    - path (str, optional): The path to the file whose content is to be hashed using MD5. Default is None.

    Returns:
    - str: If path is provided, returns the MD5 hash of the file content.\n
           If message is provided, returns the MD5 hash of the message.\n
           If neither path nor message is provided, returns a string indicating that no message or path was provided.\n
    """

    if path is not None:
        with open(path, 'rb') as f:
            hash_object = hashlib.new('md5')

            while chunk := f.read(8192):
                hash_object.update(chunk)

        file_hash = hash_object.hexdigest()
        return file_hash

    if message is not None:
        return hashlib.md5(to_bytes(message)).hexdigest()

    return "No message or path provided"


@staticmethod
def sha256(message: str = None, path: str = None) -> str:
    """
    Generate the SHA-256 hash of either a provided message or the content of a file.\n
    **Do not use for passwords**

    Parameters:
    - message (str, optional): The input message to be hashed using SHA-256. Default is None.
    - path (str, optional): The path to the file whose content is to be hashed using SHA-256. Default is None.

    Returns:
    - str: If path is provided, returns the SHA-256 hash of the file content.\n
           If message is provided, returns the SHA-256 hash of the message.\n
           If neither path nor message is provided, returns a string indicating that no message or path was provided.\n
    """
    if path is not None:
        with open(path, 'rb') as f:
            hash_object = hashlib.new('sha256')

            while chunk := f.read(8192):
                hash_object.update(chunk)

        file_hash = hash_object.hexdigest()
        return file_hash

    if message is not None:
        return hashlib.sha256(to_bytes(message)).hexdigest()

    return "No message or path provided"


@staticmethod
def sha3_256(message: str = None, path: str = None) -> str:
    """
    Generate the SHA-3-256 hash of either a provided message or the content of a file.\n
    **Do not use for passwords**

    Parameters:
    - message (str, optional): The input message to be hashed using SHA-3-256. Default is None.
    - path (str, optional): The path to the file whose content is to be hashed using SHA-3-256. Default is None.

    Returns:
    - str: If path is provided, returns the SHA-3-256 hash of the file content.\n
           If message is provided, returns the SHA-3-256 hash of the message.\n
           If neither path nor message is provided, returns a string indicating that no message or path was provided.\n
    """
    if path is not None:
        with open(path, 'rb') as f:
            hash_object = hashlib.new('sha3_256')

            while chunk := f.read(8192):
                hash_object.update(chunk)

        file_hash = hash_object.hexdigest()
        return file_hash

    if message is not None:
        return hashlib.sha3_256(to_bytes(message)).hexdigest()

    return "No message or path provided"


@staticmethod
def generate_salt(length: int = 16) -> bytes:
  try:
    salt = os.urandom(length)
    return salt
  except Exception as e:
    raise Exception(f"Something went wrong: {e}")

@staticmethod
def hash(
    message: str,
    salt: bytes = None,
    encode_hash: bool = True,
    hash_length: int = 80,
    memory_cost: int = 2**16,
    time_cost: int = 10,
    parallelism: int = 6,
    encoding: str = 'ascii'
  ):

  _salt = b""
  _formatted_message = ""

  if salt is None:
    _salt = os.urandom(16)
  else:
    _salt = salt

  _params = {
    "hash_len": hash_length,
    "salt_len": len(_salt),
    "time_cost": time_cost,
    "memory_cost": memory_cost,
    "parallelism": parallelism,
    "encoding": encoding
  }

  _hasher = argon2.PasswordHasher(**_params)

  _formatted_message = f"{message}{''.join([f'{value}' for _, value in _params.items()])}"

  _hashed_message = _hasher.hash(_formatted_message)

  return _hashed_message if not encode_hash else base64.urlsafe_b64encode(base64.a85encode(_hashed_message.encode())).decode()

@staticmethod
def verify(
    message: str,
    hashed_message: str,
    salt: bytes = None,
    encode_hash: bool = True,
    hash_length: int = 80,
    memory_cost: int = 2**16,
    time_cost: int = 10,
    parallelism: int = 6,
    encoding: str = 'ascii'
  ):

  _salt = b""
  _formatted_message = ""

  if salt is None:
    _salt = os.urandom(16)
  else:
    _salt = salt

  _params = {
    "hash_len": hash_length,
    "salt_len": len(_salt),
    "time_cost": time_cost,
    "memory_cost": memory_cost,
    "parallelism": parallelism,
    "encoding": encoding
  }

  _hasher = argon2.PasswordHasher(**_params)

  _formatted_message = f"{message}{''.join([f'{value}' for _, value in _params.items()])}"

  if encode_hash:
    _hashed_message = base64.a85decode(base64.urlsafe_b64decode(hashed_message.encode())).decode()
  else:
     _hashed_message = hashed_message

  try:
    _hasher.verify(_hashed_message, _formatted_message)
    return True
  except argon2.exceptions.VerifyMismatchError as e:
     print("Verification mismatch! The message does not match the supplied hash")
     return False
  except argon2.exceptions.VerificationError as e:
     print("Verification error!")
     print(e)
     return False
  except argon2.exceptions.InvalidHash as e:
     print("Invalid hash!")
     print(e)
     return False
  except Exception as e:
     print("Something went wrong!")
     print(e)
     return False