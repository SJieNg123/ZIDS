import re, pathlib
p = pathlib.Path(r'.\rules\input200\easylist_8.abp')
out = pathlib.Path('dataset_L8_urls.txt')
rx = re.compile(r'^\|\|([^\^/]+)\^$')
rows = []
for ln in p.read_text(encoding='utf-8').splitlines():
    ln = ln.strip()
    m = rx.match(ln)
    if not m:
        continue
    dom = m.group(1)
    rows.append(f'https://www.{dom}/')
out.write_text("\n".join(rows), encoding='utf-8')
print(f"wrote {len(rows)} urls -> {out}")
