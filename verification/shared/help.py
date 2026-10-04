"""Read only the bundled role instruction, in source and packaged layouts."""
from pathlib import Path


def documentation(module_file):
    module=Path(module_file)
    for root in (module.parents[1],module.parents[2]):
        path=root/'DOCS.md'
        if path.is_file(): return path.read_text(encoding='utf-8')
    raise ValueError('Bundled instruction unavailable')
