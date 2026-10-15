# Python: weak hash and shell injection (hand-written example, never executed)
import hashlib
import subprocess


def digest(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def archive(name: str) -> None:
    subprocess.call("tar czf backup.tgz " + name, shell=True)
