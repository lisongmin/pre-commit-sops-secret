#!/usr/bin/env python

import re


class SopsRule:
    def __init__(self, rule: dict):
        self._encrypted_regex = rule.get("encrypted_regex")
        self._path_regex = rule.get("path_regex")

        self._encrypted_patten = None
        self._path_patten = None

    def is_path_match(self, path: str) -> bool:
        if not self._path_regex:
            return False

        if not self._path_patten:
            self._path_patten = re.compile(self._path_regex)

        return self._path_patten.match(str(path)) is not None

    def is_field_match(self, key: str) -> bool:
        if not self._encrypted_regex:
            return False

        if not self._encrypted_patten:
            self._encrypted_regex = re.compile(self._encrypted_regex)

        return self._encrypted_regex.match(key) is not None
