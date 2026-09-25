from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_successful_upgrade_requires_install_marker_removed_and_no_extra_private_files(tmp_path):
    from upgrade_nextcloud import verify_configuration_files
    baseline={'CAN_INSTALL','config.sample.php','.htaccess'}
    for name in (baseline-{'CAN_INSTALL'})|{'config.php'}:(tmp_path/name).write_text('fixture')
    verify_configuration_files(tmp_path,baseline)
    for name in ('CAN_INSTALL','config.php.bak','unexpected.config.php'):
        (tmp_path/name).write_text('must stay private')
        with pytest.raises(ValueError):verify_configuration_files(tmp_path,baseline)
        (tmp_path/name).unlink()
    (tmp_path/'config.php').unlink();(tmp_path/'config.php').symlink_to(tmp_path/'config.sample.php')
    with pytest.raises(ValueError):verify_configuration_files(tmp_path,baseline)
