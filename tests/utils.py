import json
import os
from typing import Any, Dict

from pyseto.utils import base64url_decode


def get_path(name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), name)


def load_key(name: str) -> str:
    with open(get_path(name)) as key_file:
        k = key_file.read()
    return k


def load_jwk(name: str) -> Dict[str, Any]:
    with open(get_path(name)) as key_file:
        jwk = json.loads(key_file.read())
    res = {}
    res["d"] = base64url_decode(jwk["d"]) if "d" in jwk else b""
    res["x"] = base64url_decode(jwk["x"]) if "x" in jwk else b""
    res["y"] = base64url_decode(jwk["y"]) if "y" in jwk else b""

    if "d" in jwk and "x" in jwk and "y" not in jwk:
        res["x"] = b""
    return res
