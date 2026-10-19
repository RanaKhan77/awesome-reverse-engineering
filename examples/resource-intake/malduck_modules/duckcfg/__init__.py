"""Self-authored Malduck extractor for the DKCFG1 fixture: marker, 8-byte RC4 key, uint16 length, ciphertext."""
from malduck import Extractor, rc4


class DuckCfg(Extractor):
    family = "duckcfg"
    yara_rules = ("duckcfg",)

    @Extractor.string("cfg")
    def config_block(self, p, addr, match):
        key = p.readv(addr + 6, 8)
        size = p.uint16v(addr + 14)
        plain = rc4(key, p.readv(addr + 16, size))
        if not plain.startswith(b"c2="):
            return None
        config = {"family": self.family, "urls": []}
        for field in plain.decode("ascii").split(";"):
            name, value = field.split("=", 1)
            if name == "c2":
                config["urls"].append(value)
            elif name == "campaign":
                config["campaign"] = value
            elif name == "sleep":
                config["sleep"] = int(value)
        return config
