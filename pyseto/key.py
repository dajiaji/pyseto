from typing import Union

from .versions.v1 import V1Local, V1Public
from .versions.v2 import V2Local, V2Public
from .versions.v3 import V3Local, V3Public
from .versions.v4 import V4Local, V4Public


class Key:
    @staticmethod
    def new(version: str, type: str, key: Union[bytes, str] = b""):
        if type != "local" and type != "public":
            raise ValueError(f"Invalid type: {type}")
        if version == "v1":
            return V1Public(key) if type == "public" else V1Local(key)
        if version == "v2":
            return V2Public(key) if type == "public" else V2Local(key)
        if version == "v3":
            return V3Public(key) if type == "public" else V3Local(key)
        if version == "v4":
            return V4Public(key) if type == "public" else V4Local(key)
        raise ValueError(f"Invalid version: {version}")
