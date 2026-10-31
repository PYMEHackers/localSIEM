#!/usr/bin/env -S PYTHONDONTWRITEBYTECODE=1 python3

import hashlib
import hmac
import secrets

cPasswordIterations = 600000


def fHashPassword(pPassword: str) -> str:
  vSalt = secrets.token_hex(16)
  vDigest = hashlib.pbkdf2_hmac(
    "sha256", pPassword.encode("utf-8"), bytes.fromhex(vSalt), cPasswordIterations
  ).hex()
  return "pbkdf2_sha256$" + str(cPasswordIterations) + "$" + vSalt + "$" + vDigest


def fVerifyPassword(pPassword: str, pStoredHash: str) -> bool:
  try:
    vAlgorithm, vIterations, vSalt, vExpected = pStoredHash.split("$")
    if vAlgorithm != "pbkdf2_sha256" or not 100000 <= int(vIterations) <= 2000000:
      return False
    vDigest = hashlib.pbkdf2_hmac(
      "sha256", pPassword.encode("utf-8"), bytes.fromhex(vSalt), int(vIterations)
    ).hex()
    return hmac.compare_digest(vDigest, vExpected)
  except (ValueError, TypeError):
    return False
