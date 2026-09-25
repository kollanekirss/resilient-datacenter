"""Real Element browser acceptance against the disposable trusted-HTTPS fixture."""
import os
from pathlib import Path
import subprocess
import urllib.parse
from contextlib import contextmanager


@contextmanager
def session():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Browser acceptance is restricted to the disposable CI fixture')
    from playwright.sync_api import sync_playwright,expect
    nss=Path('/root/.pki/nssdb');nss.mkdir(parents=True,mode=0o700,exist_ok=True)
    if not (nss/'cert9.db').exists():
        subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(nss)],check=True,capture_output=True)
        subprocess.run(['certutil','-A','-d','sql:'+str(nss),'-n','RDC disposable application CA','-t','C,,',
                        '-i','/usr/local/share/ca-certificates/rdc-application-ci.crt'],check=True,capture_output=True)
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch()
        context=browser.new_context(ignore_https_errors=False,permissions=['clipboard-read','clipboard-write'])
        page=context.new_page();page.set_default_timeout(60000)
        try:
            yield page
        except Exception:
            # Diagnostic labels only; never dump tokens, storage, keys or password inputs.
            print('Element visible headings: '+repr(page.get_by_role('heading').all_text_contents()),flush=True)
            print('Element visible buttons: '+repr(page.get_by_role('button').all_text_contents()),flush=True)
            raise ValueError('Element browser acceptance failed; inspect the reported screen labels. Private inputs are withheld.') from None
        finally:context.close();browser.close()


def encryption_settings(page):
    page.get_by_role('button',name='User menu',exact=True).click()
    page.get_by_role('menuitem',name='All settings',exact=True).click()
    page.locator('.mx_TabbedView_tabLabel').filter(has_text='Encryption').click()
    return page.locator('.mx_Dialog').filter(has=page.locator('.mx_UserSettingsDialog'))


def login(page,username,password,*,recovery_key=None):
    from playwright.sync_api import expect
    page.goto('https://chat.ci.test/#/login')
    page.get_by_role('textbox',name='Username').fill(username)
    page.get_by_placeholder('Password',exact=True).fill(password)
    page.get_by_role('button',name='Sign in',exact=True).click()
    user_menu=page.get_by_role('button',name='User menu',exact=True)
    if recovery_key is not None:
        recovery=page.get_by_role('button',name='Use recovery key',exact=True)
        expect(user_menu.or_(recovery).first).to_be_visible()
        if not recovery.is_visible():
            dialog=encryption_settings(page)
            dialog.get_by_role('button',name='Verify this device',exact=True).click()
        page.get_by_role('button',name='Use recovery key',exact=True).click()
        dialog=page.locator('.mx_Dialog')
        extra=dialog.get_by_role('button',name='Use recovery key',exact=True)
        if extra.is_visible():extra.click()
        dialog.get_by_title('Recovery key',exact=True).fill(recovery_key)
        dialog.get_by_role('button',name='Continue',exact=True).click()
        page.get_by_role('button',name='Done',exact=True).click()
        close=page.get_by_role('button',name='Close dialog',exact=True)
        if close.is_visible():close.click()
    expect(user_menu).to_be_visible()


def prepare_encrypted(username,password,room,backup_check):
    from playwright.sync_api import expect
    with session() as page:
        login(page,username,password)
        dialog=encryption_settings(page)
        toggle=dialog.get_by_role('switch',name='Allow key storage',exact=True)
        if not toggle.is_checked():toggle.click()
        dialog.get_by_role('button',name='Get recovery key',exact=True).click()
        dialog.get_by_role('button',name='Continue',exact=True).click()
        dialog.get_by_role('button',name='Copy',exact=True).click()
        recovery_key=page.evaluate('navigator.clipboard.readText()')
        if not isinstance(recovery_key,str) or len(recovery_key)<40:raise ValueError('Recovery key was not produced')
        dialog.get_by_role('button',name='Continue',exact=True).click()
        dialog.get_by_role('textbox').fill(recovery_key)
        dialog.get_by_role('button',name='Finish set up',exact=True).click()
        expect(dialog.get_by_role('button',name='Change recovery key',exact=True)).to_be_visible()
        page.get_by_role('button',name='Close dialog',exact=True).click()
        page.goto('https://chat.ci.test/#/room/'+urllib.parse.quote(room,safe=''))
        composer=page.locator('.mx_MessageComposer').get_by_role('textbox')
        composer.fill('Encrypted history survives restored server and fresh browser')
        with page.expect_response(lambda response:'/send/m.room.encrypted/' in response.url and response.request.method=='PUT') as sent:
            composer.press('Enter')
        assert sent.value.status==200 and sent.value.json().get('event_id')
        expect(page.get_by_text('Encrypted history survives restored server and fresh browser',exact=True)).to_be_visible()
        for attempt in range(30):
            if backup_check():break
            page.wait_for_timeout(1000)
        else:raise ValueError('Browser did not upload the encrypted room key before closing')
        print('Element encrypted message and independently captured test recovery key prepared; recovery not yet claimed.',flush=True)
        return recovery_key


def exercise(username,password,room,*,recovery_key=None,encrypted_room=None):
    from playwright.sync_api import expect
    with session() as page:
        login(page,username,password,recovery_key=recovery_key)
        page.goto('https://chat.ci.test/#/room/'+urllib.parse.quote(room,safe=''))
        expect(page.get_by_text('Disposable RDC application proof',exact=True)).to_be_visible()
        composer=page.locator('.mx_MessageComposer').get_by_role('textbox')
        composer.fill('Message sent from the actual Element browser')
        with page.expect_response(lambda response:'/send/m.room.message/' in response.url and response.request.method=='PUT') as sent:
            composer.press('Enter')
        assert sent.value.status==200 and sent.value.json().get('event_id')
        expect(page.get_by_text('Message sent from the actual Element browser',exact=True)).to_be_visible()
        if encrypted_room is not None:
            page.goto('https://chat.ci.test/#/room/'+urllib.parse.quote(encrypted_room,safe=''))
            expect(page.get_by_text('Encrypted history survives restored server and fresh browser',exact=True)).to_be_visible(timeout=90000)
            print('Actual fresh Element browser recovered encrypted history after server restore using the independently held recovery key PASS.',flush=True)
        print('Actual Element browser: trusted certificate, password login, restored history display and message composer PASS.',flush=True)
