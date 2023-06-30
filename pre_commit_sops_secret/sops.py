#!/usr/bin/env python

import base64
import binascii
import shutil
from pathlib import Path
from subprocess import check_call
import yaml
from .sops_rule import SopsRule


class Sops:
    def __init__(self):
        self._tmp_file_prefix = "base64-encoded-"
        self._rules: list[SopsRule] = []

    def load_sops_rules(self, sops_config_file: Path):
        sops_config = yaml.safe_load(sops_config_file.read_text())
        for rule in sops_config.get("creation_rules", []):
            self._rules.append(SopsRule(rule))

    def encrypt(self, file: Path) -> bool:
        """
        This function encrypt the specified file with sops.

        1. If the file path starts with tmp file prefix or is not matching any sops rule,
        encrypt action will be ignored and return immediately.
        2. If this file is already encrypted (contains top level "sops" field),
        encrypt action will be ignored and return immediately.
        3. for each data field to encrypt, ensure the value is base64 encoding,
        encode it if not.
        4. call sops to encrypt this file

        This function will return True if the file changed else return False
        """
        if file.name.startswith(self._tmp_file_prefix):
            return False

        rules = self.match_path_regex(file)
        if not rules:
            return False

        content = yaml.safe_load(file.open())
        if not content:
            return False

        if "sops" in content:
            return False

        for rule in rules:
            content = self.encode_by_rule(rule, content)

        tmp_file = Path(file.parent).joinpath(f"{self._tmp_file_prefix}{file.name}")
        yaml.safe_dump(content, tmp_file.open('w'))

        self.do_encrypt(tmp_file)
        shutil.move(tmp_file, file)

        return True

    def match_path_regex(self, file: Path):
        return [rule for rule in self._rules if rule.is_path_match(file)]

    def encode_by_rule(self, rule: SopsRule, content: [dict, str], should_encode=False):
        if isinstance(content, dict):
            return {key: self.encode_by_rule(rule, sub_content, should_encode or rule.is_field_match(key))
                    for key, sub_content in content.items()}

        if isinstance(content, list):
            return [self.encode_by_rule(rule, sub_content, should_encode) for sub_content in content]

        if isinstance(content, str):
            if should_encode:
                try:
                    base64.b64decode(content, validate=True)
                    return content
                except binascii.Error:
                    return base64.b64encode(content.encode())

        return content

    def do_encrypt(rule: SopsRule, file: Path):
        check_call(["sops", "-e", "-i", file])
