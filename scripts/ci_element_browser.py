"""Real Element browser acceptance against the disposable trusted-HTTPS fixture."""
import os
from pathlib import Path
import subprocess
import urllib.parse


def exercise(username,password,room):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Browser acceptance is restricted to the disposable CI fixture')
    from playwright.sync_api import sync_playwright,expect
    nss=Path('/root/.pki/nssdb');nss.mkdir(parents=True,mode=0o700)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(nss)],check=True,capture_output=True)
    subprocess.run(['certutil','-A','-d','sql:'+str(nss),'-n','RDC disposable application CA','-t','C,,',
                    '-i','/usr/local/share/ca-certificates/rdc-application-ci.crt'],check=True,capture_output=True)
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch()
        context=browser.new_context(ignore_https_errors=False)
        page=context.new_page();page.set_default_timeout(60000)
        try:
            page.goto('https://chat.ci.test/#/login')
            page.get_by_role('textbox',name='Username').fill(username)
            page.get_by_placeholder('Password',exact=True).fill(password)
            page.get_by_role('button',name='Sign in',exact=True).click()
            expect(page.get_by_role('button',name='User menu',exact=True)).to_be_visible()
            page.goto('https://chat.ci.test/#/room/'+urllib.parse.quote(room,safe=''))
            expect(page.get_by_text('Disposable RDC application proof',exact=True)).to_be_visible()
            composer=page.locator('.mx_MessageComposer').get_by_role('textbox')
            composer.fill('Message sent from the actual Element browser')
            composer.press('Enter')
            expect(page.get_by_text('Message sent from the actual Element browser',exact=True)).to_be_visible()
            print('Actual Element browser: trusted certificate, password login, restored history display and message composer PASS.',flush=True)
        except Exception:
            # Diagnostic labels only; never dump tokens, storage, keys or password inputs.
            print('Element visible headings: '+repr(page.get_by_role('heading').all_text_contents()),flush=True)
            print('Element visible buttons: '+repr(page.get_by_role('button').all_text_contents()),flush=True)
            raise
        finally:context.close();browser.close()
