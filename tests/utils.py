import os


def get_path(name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), name)
