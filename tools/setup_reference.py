"""Install a pinned offline test oracle, without npm, browsers or install scripts."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile


def main():
    workspace = Path(__file__).resolve().parents[1]
    lock = json.loads((workspace/'tools/reference-lock.json').read_text())
    url = f"https://codeload.github.com/adblockplus/adblockpluscore/zip/{lock['commit']}"
    data = urllib.request.urlopen(url, timeout=30).read()
    if hashlib.sha256(data).hexdigest() != lock['archive_sha256']:
        raise RuntimeError('reference archive hash mismatch')
    root = (workspace/'.reference/abp').resolve()
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            name = entry.filename.split('/', 1)[-1]
            if entry.is_dir() or not (name.startswith(('lib/', 'data/')) or name in ('COPYING', 'package.json')):
                continue
            destination = (root/name).resolve()
            if not destination.is_relative_to(root):
                raise RuntimeError('unsafe archive path')
            content = archive.read(entry)
            if destination.exists() and destination.read_bytes() != content:
                raise RuntimeError(f'reference file already differs: {name}')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
    print(json.dumps({'commit': lock['commit'], 'oracle': str(root)}))


if __name__ == '__main__':
    main()
