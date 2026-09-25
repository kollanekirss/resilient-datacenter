from test_nextcloud_contracts import profile
import importlib
from pathlib import Path
import pytest


def test_pinned_code_links_must_stay_within_readonly_application_tree(tmp_path):
    m=importlib.import_module('nextcloud_operations');root=tmp_path/'application';root.mkdir()
    (root/'asset.js').write_text('pinned asset');(root/'alias.js').symlink_to('asset.js')
    assert root/'alias.js' in m.code_entries(root)
    (root/'escape').symlink_to(tmp_path/'outside')
    (tmp_path/'outside').write_text('unowned')
    with pytest.raises(ValueError):m.code_entries(root)
    (root/'escape').unlink();(root/'broken').symlink_to('absent')
    with pytest.raises(ValueError):m.code_entries(root)
