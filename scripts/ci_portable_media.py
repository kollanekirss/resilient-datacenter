#!/usr/bin/env python3
"""Download real vendor media on disposable CI; never boot or execute it."""
import json
import tempfile
from pathlib import Path
from guest_media import prepare, verify


def main():
    with tempfile.TemporaryDirectory(prefix='rdc-media-') as temporary:
        cache=Path(temporary)/'cache'
        for kind in ('opnsense','ubuntu'):
            record=prepare(kind,cache)
            assert verify(cache,kind)==record
            print(json.dumps(record),flush=True)
    print('Vendor media hashes and decompression verified. Guest boot and Proxmox installation NOT RUN.',flush=True)


if __name__=='__main__':main()
