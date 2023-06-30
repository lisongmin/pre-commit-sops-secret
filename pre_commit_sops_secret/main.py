#!/usr/bin/env python

from pathlib import Path
import click
from .sops import Sops


@click.command()
@click.option("--sops-config", default=Path(".sops.yaml"), type=click.Path(), show_default=True)
@click.argument("files", nargs=-1, type=click.Path(exists=True))
def encrypt(sops_config: Path, files: list[str]):
    if not sops_config.exists():
        print(f"Sops config file '{sops_config}' does not exists, ignore checking")
        return 0

    sops = Sops()
    sops.load_sops_rules(sops_config)

    changed_files = []
    for file in files:
        if sops.encrypt(Path(file)):
            changed_files.append(file)

    return 0
