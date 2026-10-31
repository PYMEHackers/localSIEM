"""Time-based one-time passwords (RFC 6238), as in the SOC.

Any authenticator app works: SHA-1, 6 digits, 30-second steps, one step of
tolerance on each side for clock drift. A step already used is never
accepted again. The account shows as «PYMEHackers localSIEM» in the app.
"""

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
import urllib.parse

cIssuer = "PYMEHackers localSIEM"
cDigits = 6
cPeriodSeconds = 30
cDriftSteps = 1


def fNewSecret() -> str:
  # 160 random bits in base32, as the authenticator apps expect.
  return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def fCodeForStep(pSecret: str, pStep: int) -> str:
  vKey = base64.b32decode(pSecret + "=" * (-len(pSecret) % 8), casefold=True)
  vDigest = hmac.new(vKey, struct.pack(">Q", pStep), hashlib.sha1).digest()
  vOffset = vDigest[-1] & 0x0F
  vNumber = struct.unpack(">I", vDigest[vOffset:vOffset + 4])[0] & 0x7FFFFFFF
  return str(vNumber % (10 ** cDigits)).zfill(cDigits)


def fCurrentStep() -> int:
  return int(time.time()) // cPeriodSeconds


def fMatchCode(pSecret: str, pCode: str, pLastStep: int) -> int | None:
  # Returns the step the code belongs to, or None. Steps up to pLastStep
  # were already used and are refused (a code cannot be replayed).
  vCode = re.sub(r"\s+", "", str(pCode or ""))
  if not re.fullmatch(r"\d{%d}" % cDigits, vCode):
    return None
  vNow = fCurrentStep()
  for vStep in range(vNow - cDriftSteps, vNow + cDriftSteps + 1):
    if vStep > int(pLastStep or 0) and hmac.compare_digest(fCodeForStep(pSecret, vStep), vCode):
      return vStep
  return None


def fOtpauthUri(pSecret: str) -> str:
  # Only «PYMEHackers localSIEM» in the label, with no separate issuer that
  # some apps would show next to it.
  vLabel = urllib.parse.quote(cIssuer)
  dParameters = {"secret": pSecret, "algorithm": "SHA1", "digits": cDigits, "period": cPeriodSeconds}
  return f"otpauth://totp/{vLabel}?{urllib.parse.urlencode(dParameters, quote_via=urllib.parse.quote)}"


def fQrDataUri(pText: str) -> str:
  # SVG QR code as a data: URI. Without segno the page still shows the
  # secret to type by hand.
  try:
    import segno
    return segno.make(pText, error="m").svg_data_uri(scale=5, border=2, dark="#1a1a1a", light="#ffffff")
  except Exception:
    return ""
