import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests

from osint_tool.core.config import AppConfig, EMAIL_ACCOUNT_SITES
from osint_tool.core.http import build_session
from osint_tool.modules.phone import PhoneModule
from osint_tool.modules.email_osint import EmailModule
from osint_tool.modules.face_recognition import FaceModule
from osint_tool.web import app as web
from osint_tool.core.network import public_addresses, public_socket


class SecurityTests(unittest.TestCase):
    def test_private_targets_are_blocked_and_public_sockets_are_pinned(self):
        for address in ('127.0.0.1','10.0.0.1','192.168.0.1','169.254.169.254','224.0.0.1','::1','::ffff:127.0.0.1'):
            with patch('socket.getaddrinfo', return_value=[(0,0,0,'',(address,443))]), self.assertRaises(ValueError):
                public_addresses('untrusted.example',443)
        with patch('socket.getaddrinfo', return_value=[(0,0,0,'',('8.8.8.8',443))]), \
             patch('socket.create_connection') as connect:
            public_socket('public.example',443,8)
            connect.assert_called_once_with(('8.8.8.8',443),timeout=8)
        with build_session() as session, patch('socket.create_connection') as connect:
            session.trust_env = False
            with self.assertRaises(ValueError): session.get('http://127.0.0.1',timeout=1)
            connect.assert_not_called()

    def test_netrc_is_never_used_including_after_redirect(self):
        with build_session() as session, patch('requests.sessions.get_netrc_auth', return_value=('private','secret')) as auth:
            prepared = session.prepare_request(requests.Request('GET','https://example.com'))
            self.assertNotIn('Authorization', prepared.headers)
            response = requests.Response()
            response.request = prepared
            session.rebuild_auth(prepared, response)
            auth.assert_not_called()

    def test_redirects_do_not_forward_custom_login_headers(self):
        with build_session() as session:
            original = session.prepare_request(requests.Request('GET','https://example.com', headers={
                'Authorization':'Bearer private', 'X-Custom-Key':'private', 'hibp-api-key':'private', 'Cookie':'secret=1'}))
            response = requests.Response(); response.request = original
            redirected = original.copy(); redirected.url = 'https://different.example/path'
            session.rebuild_auth(redirected, response)
            for name in ('Authorization','X-Custom-Key','hibp-api-key','Cookie'):
                self.assertNotIn(name, redirected.headers)
            redirected.url = 'http://example.com'
            with self.assertRaises(requests.exceptions.InvalidURL):
                session.rebuild_auth(redirected, response)
            redirected.url = 'https://different.example'; redirected.body = 'email=private@example.com'
            with self.assertRaises(requests.exceptions.InvalidURL):
                session.rebuild_auth(redirected, response)

    def test_api_keys_are_removed_from_error_reports(self):
        module = PhoneModule(AppConfig(api_keys={'numverify':'private/key+value'}))
        module.add_error('request failed: ?access_key=private%2Fkey%2Bvalue; private/key+value')
        self.assertNotIn('private', module._errors[0])

    def test_recovery_and_signin_checks_never_make_requests(self):
        module = EmailModule()
        session = MagicMock()
        site = next(s for s in EMAIL_ACCOUNT_SITES if '/password/restore' in s['url'])
        result = module._check_account_site(site, module._tokens('test@example.com'), session)
        self.assertEqual(result['verdict'], 'inconclusive')
        self.assertEqual(session.mock_calls, [])
        with patch.object(module, '_fresh_session', side_effect=AssertionError('No login request')):
            self.assertEqual(module._chk_amazon('test@example.com')['verdict'], 'inconclusive')
            self.assertEqual(module._chk_ebay('test@example.com')['verdict'], 'inconclusive')

    def test_network_image_paths_are_rejected_before_filesystem_access(self):
        with patch('osint_tool.modules.face_recognition.os.path.exists') as exists:
            for path in (r'\\server\image.jpg', '//server/image.jpg', r'\\?\UNC\server\image.jpg', 'file://server/image.jpg'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    FaceModule().run(path)
            exists.assert_not_called()

    def test_local_web_rejects_remote_sites_and_missing_tokens(self):
        client = web.app.test_client()
        self.assertEqual(client.get('/api/modules').status_code, 403)
        self.assertEqual(client.get('/', headers={'Host':'attacker.example'}).status_code, 403)
        self.assertEqual(client.get('/', environ_overrides={'REMOTE_ADDR':'192.168.1.10'}).status_code, 403)
        root = client.get('/')
        self.assertEqual(root.status_code, 200)
        self.assertIn('HttpOnly',root.headers['Set-Cookie'])
        self.assertIn('SameSite=Strict',root.headers['Set-Cookie'])
        self.assertEqual(client.post('/api/scan',json={'input':'test'}).status_code, 403)
        self.assertEqual(client.get('/api/modules',headers={'Origin':'https://attacker.example'}).status_code, 403)
        self.assertEqual(client.get('/api/modules',headers={'Sec-Fetch-Site':'cross-site'}).status_code, 403)
        with self.assertRaises(ValueError): web.start_server(host='0.0.0.0')
        with self.assertRaises(ValueError): web.start_server(debug=True)

    def test_scan_limit_is_enforced_before_starting_another_worker(self):
        client = web.app.test_client(); client.get('/')
        with patch.dict(web.scan_states, {'one':{'status':'running'}, 'two':{'status':'running'}}, clear=True), \
             patch.object(web.threading, 'Thread') as thread:
            result = client.post('/api/scan',json={'input':'test'},headers={'X-OSINT-Token':web.app.config['LOCAL_TOKEN']})
            self.assertEqual(result.status_code,429)
            thread.assert_not_called()


if __name__ == '__main__':
    unittest.main()
