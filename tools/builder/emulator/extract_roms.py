# Split an Emscripten file_packager bundle (load-rom.js + load-rom.data) into plain files.
#   python3 -I extract_roms.py load-rom.js load-rom.data outdir [name ...]
import json
import os
import re
import sys

js, data, out = sys.argv[1:4]
want = set(sys.argv[4:])
meta = json.loads(re.search(r"loadPackage\((\{.*\})\);\s*\}\)\(\);", open(js).read(), re.S).group(1))
blob = open(data, 'rb').read()
os.makedirs(out, exist_ok=True)
for f in meta['files']:
    name = os.path.basename(f['filename'])
    if want and name not in want:
        continue
    open(os.path.join(out, name), 'wb').write(blob[f['start']:f['end']])
    print(name, f['end'] - f['start'])
