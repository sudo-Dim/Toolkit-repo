import json
import unittest
from unittest.mock import Mock, patch

import requests

from osint_tool.core.config import AppConfig, USERNAME_PLATFORMS, EMAIL_ACCOUNT_SITES
from osint_tool.core.evidence import profile_evidence
from osint_tool.desktop.app import matches_filter, result_status
from osint_tool.modules.base import ResultSeverity
from osint_tool.modules.email_osint import EmailModule
from osint_tool.modules.name_search import NameModule
from osint_tool.modules.username import UsernameModule


def response(url, body='', status=200, content_type='text/html'):
    result = requests.Response()
    result.url = url
    result.status_code = status
    result.encoding = 'utf-8'
    result.headers['Content-Type'] = content_type
    result._content = body.encode('utf-8')
    result._content_consumed = True
    return result


SOURCES = {source['name']: source for source in USERNAME_PLATFORMS}


class ProfileEvidenceTests(unittest.TestCase):
    def test_generic_success_and_block_pages_never_become_hits_for_any_source(self):
        pages = ['<title>Welcome</title>', '<title>Sign in</title>',
                 '<title>Just a moment...</title>', '<form id="challenge-form"></form>',
                 '<title>Profile not found</title>', '{}', '[]', 'null', 'true']
        for source in USERNAME_PLATFORMS:
            url = source.get('url_probe', source['url']).replace('{}', 'example')
            for page in pages:
                with self.subTest(source=source['name'], page=page):
                    self.assertNotEqual(profile_evidence(source, 200, page, url, 'example')[0], 'found')

    def test_profile_api_requires_matching_identifier_and_same_record(self):
        source = SOURCES['GitLab']; url = source['url_probe'].replace('{}', 'example')
        for payload in ([{'username': 'someone-else', 'id': 1}],
                        [{'username': 'example'}, {'id': 2}],
                        [{'username': 'example', 'id': True}],
                        {'error': 'example'}):
            self.assertEqual(profile_evidence(source, 200, json.dumps(payload), url, 'example')[0], 'uncertain')
        self.assertEqual(profile_evidence(source, 200, '[{"username":"Example","id":123}]', url, 'example')[0], 'found')
        self.assertEqual(profile_evidence(source, 200, '[]', url, 'example')[0], 'not_found')
        github = SOURCES['GitHub']; github_url = github['url_probe'].replace('{}', 'example')
        self.assertEqual(profile_evidence(github, 200, '{"login":"example","id":123,"error":"limited"}', github_url, 'example')[0], 'uncertain')

    def test_curated_api_shapes_for_existing_and_new_sources(self):
        # Independent schema examples, not generated from the matching configuration.
        examples = {
            'GitHub': {'login': 'example', 'id': 100},
            'Codeberg': {'login': 'example', 'id': 100},
            'Gitea.com': {'login': 'example', 'id': 100},
            'GitLab': [{'username': 'example', 'id': 100}],
            'Debian Salsa': [{'username': 'example', 'id': 100}],
            'GNOME GitLab': [{'username': 'example', 'id': 100}],
            'KDE Invent': [{'username': 'example', 'id': 100}],
            'Dev.to': {'username': 'example', 'id': 100},
            'Docker Hub': {'username': 'example', 'date_joined': '2020-01-01'},
            'HackerNews': {'id': 'example', 'created': 12345},
            'Bluesky': {'handle': 'example.bsky.social', 'did': 'did:plc:test'},
            'Mastodon.social': {'acct': 'example', 'id': '100'},
            'Trello': {'username': 'example', 'id': 'test-id'},
            'Mixcloud': {'username': 'example', 'key': '/example/'},
            'Lichess': {'username': 'example', 'id': 'example'},
            'Chess.com': {'username': 'example', 'player_id': 100},
            'Wattpad': {'name': 'example', 'id': 100},
            'Dailymotion': {'username': 'example', 'id': 'x100'},
            'Keybase': {'them': [{'basics': {'username': 'example'}, 'id': 'test-id'}]},
            'Codewars': {'username': 'example', 'id': 'test-id'},
            'Codeforces': {'status': 'OK', 'result': [{'handle': 'example', 'registrationTimeSeconds': 12345}]},
            'Scratch': {'username': 'example', 'id': 100},
            'Discogs': {'username': 'example', 'id': 100},
            'iNaturalist': {'results': [{'login': 'example', 'id': 100}]},
            'Open Library': {'key': '/people/example', 'type': {'key': '/type/user'}},
            'Launchpad': {'name': 'example', 'self_link': 'https://api.launchpad.net/1.0/~example'},
            'Lemmy.world': {'person_view': {'person': {'name': 'example', 'id': 100}}},
            'Lemmy.ml': {'person_view': {'person': {'name': 'example', 'id': 100}}},
        }
        for name, body in examples.items():
            source = SOURCES[name]; url = source['url_probe'].replace('{}', 'example')
            with self.subTest(source=name):
                self.assertEqual(profile_evidence(source, 200, json.dumps(body), url, 'example')[0], 'found')
                for status in (403, 429, 500):
                    self.assertEqual(profile_evidence(source, status, json.dumps(body), url, 'example')[0], 'uncertain')
                self.assertEqual(profile_evidence(source, 200, json.dumps(body), url, 'different')[0], 'uncertain')

    def test_redirect_and_search_pages_do_not_prove_a_profile(self):
        source = {'url': 'https://example.com/users/{}', 'evidence': {'kind': 'html'}}
        html = '<link href="https://example.com/users/alice" rel="canonical">'
        for final in ('https://example.com/login', 'https://example.com/', 'https://other.example/users/alice'):
            self.assertEqual(profile_evidence(source, 200, html, final, 'alice')[0], 'uncertain')
        self.assertEqual(profile_evidence(source, 200, html, 'https://example.com/users/alice', 'alice')[0], 'candidate')
        generic_route = {'url': 'https://example.com/{}', 'evidence': {'kind': 'html'}}
        self.assertEqual(profile_evidence(generic_route, 200, '<link rel="canonical" href="/about">', 'https://example.com/about', 'about')[0], 'uncertain')

    def test_html_wildcard_profiles_require_a_negative_control(self):
        source = {'name': 'Example', 'url': 'https://example.com/users/{}', 'evidence': {'kind': 'html'}}
        module = UsernameModule()
        session = Mock()
        def serve(url, **kwargs):
            return response(url, f'<link rel="canonical" href="{url}">')
        session.get.side_effect = serve
        self.assertEqual(module._check_platform(source, 'alice', session)['verdict'], 'uncertain')
        self.assertEqual(session.get.call_count, 2)
        def missing_control(url, **kwargs):
            return serve(url) if url.endswith('/alice') else response(url, '<title>404 Not Found</title>', 404)
        session.get.side_effect = missing_control
        self.assertEqual(module._check_platform(source, 'alice', session)['verdict'], 'found')
        session.get.side_effect = lambda url, **kwargs: serve(url) if url.endswith('/alice') else response(url, '', 429)
        self.assertEqual(module._check_platform(source, 'alice', session)['verdict'], 'uncertain')

    def test_json_needs_only_one_request_and_oversized_pages_are_unknown(self):
        source = SOURCES['GitHub']; session = Mock(); module = UsernameModule()
        url = source['url_probe'].replace('{}', 'alice')
        session.get.return_value = response(url, '{"login":"alice","id":123}', content_type='application/json')
        self.assertEqual(module._check_platform(source, 'alice', session)['verdict'], 'found')
        self.assertEqual(session.get.call_count, 1)
        session.get.return_value = response(url, 'x' * (2 * 1024 * 1024 + 1))
        self.assertEqual(module._check_platform(source, 'alice', session)['verdict'], 'uncertain')

    def test_manual_sources_stay_manual_even_with_credentials(self):
        module = UsernameModule(AppConfig(probe_unreliable=True, site_auth={'Instagram': {'cookie': 'test'}}))
        with patch('osint_tool.modules.username.USERNAME_PLATFORMS', [SOURCES['Instagram']]), patch.object(module, '_session') as session:
            report = module.run('example')
        self.assertEqual(report.found_count, 0)
        self.assertEqual(report.results[0].data['verdict'], 'manual')
        session.return_value.get.assert_not_called()


class AccountEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.module = EmailModule()
        self.tokens = self.module._tokens('test@example.com')

    def check(self, site, body, status=200, final_url=None):
        url = self.module._tmpl(site['url'], self.tokens)
        session = Mock()
        session.get.return_value = session.post.return_value = response(final_url or url, body, status)
        return self.module._check_account_site(site, self.tokens, session)

    def test_http_failure_cannot_confirm_account_from_body(self):
        site = next(s for s in EMAIL_ACCOUNT_SITES if s['name'] == 'Spotify')
        for status in (401, 403, 429, 500):
            self.assertEqual(self.check(site, '{"status":20}', status)['verdict'], 'inconclusive')
        self.assertEqual(self.check(site, '{"status":20}')['verdict'], 'exists')
        self.assertEqual(self.check(site, '{"status":20}', final_url='https://other.example/login')['verdict'], 'inconclusive')

    def test_federated_and_throttled_microsoft_results_are_not_accounts(self):
        site = next(s for s in EMAIL_ACCOUNT_SITES if s['name'].startswith('Microsoft'))
        for code in (False, True, 1, 2, 5, 6):
            self.assertEqual(self.check(site, json.dumps({'IfExistsResult': code, 'ThrottleStatus': 0}))['verdict'], 'inconclusive')
        self.assertEqual(self.check(site, '{"IfExistsResult":0,"ThrottleStatus":1}')['verdict'], 'inconclusive')
        self.assertEqual(self.check(site, '{"IfExistsResult":0,"ThrottleStatus":0}')['verdict'], 'hint')

    def test_conflicting_and_wrongly_typed_signals_are_unknown(self):
        site = {'name': 'Test', 'url': 'https://example.com/check',
                'exists': [{'json': 'taken', 'eq': True}], 'notexists': [{'json': 'free', 'eq': True}]}
        for body in ('{"taken":true,"free":true}', '{"taken":1}', '{}'):
            self.assertEqual(self.check(site, body)['verdict'], 'inconclusive')
        self.assertFalse(self.module._eval_rule({'json': 'value', 'in': [0, 1]}, 200, '', {'value': False}))

    def test_gravatar_html_success_is_not_an_avatar_or_profile(self):
        session = Mock(); session.head.return_value = response('https://gravatar.com', '<title>Sign in</title>')
        session.get.return_value = response('https://gravatar.com', '{"entry":[{"hash":"wrong","displayName":"Other"}]}')
        result = self.module._check_gravatar('test@example.com', session)
        self.assertFalse(result['has_avatar'])
        self.assertIsNone(result['profile'])

    def test_breach_search_substrings_and_empty_results_are_not_hits(self):
        session = Mock()
        session.get.return_value = response('https://api.proxynova.com', json.dumps({
            'count': 1, 'lines': ['nottest@example.com:synthetic-password']}))
        self.assertIsNone(self.module._breach_proxynova('test@example.com', session))
        session.get.return_value = response('https://api.proxynova.com', json.dumps({
            'count': 99, 'lines': ['test@example.com:synthetic-password', 'nottest@example.com:other']}))
        result = self.module._breach_proxynova('test@example.com', session)
        self.assertTrue(result['found'])
        self.assertEqual(result['count'], 1)
        self.assertNotIn('synthetic-password', json.dumps(result))
        session.get.return_value = response('https://haveibeenpwned.com', '[]')
        module = EmailModule(AppConfig(api_keys={'hibp': 'test-key'}))
        self.assertFalse(module._breach_hibp('test@example.com', session)['found'])

    def test_github_search_candidate_is_not_an_exact_email_match(self):
        session = Mock()
        session.get.side_effect = [response('https://api.github.com', '{"total_count":0}'),
            response('https://api.github.com', '{"total_count":1,"items":[{"login":"someone","html_url":"https://github.com/someone"}]}'),
            response('https://api.github.com', '{"login":"someone","email":"other@example.com"}')]
        result = self.module._check_github('test@example.com', session)
        self.assertIsNone(result['user'])
        self.assertEqual(result['candidate']['login'], 'someone')

    def test_name_matches_are_candidates_not_verified_people(self):
        module = NameModule()
        with patch.object(module, '_session'), patch.object(module, '_orcid', return_value=[{'url': 'https://orcid.org/test'}]), \
             patch.object(module, '_github_users', return_value=[{'url': 'https://github.com/example'}]):
            report = module.run('Example Person')
        self.assertEqual(report.found_count, 0)
        candidates = [result for result in report.results if result.data.get('verdict') == 'candidate']
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(result.severity == ResultSeverity.INFO for result in candidates))

    def test_gui_separates_manual_links_candidates_and_hits(self):
        for verdict in ('candidate', 'uncertain', 'manual'):
            row = {'severity': 'info', 'data': {'verdict': verdict}}
            self.assertFalse(matches_filter(row, 'Treffer'))
            self.assertEqual(matches_filter(row, 'Manuelle Quellen'), verdict == 'manual')
            self.assertEqual(matches_filter(row, 'Unbestätigt'), verdict != 'manual')
            self.assertNotEqual(result_status(row), 'Treffer')


if __name__ == '__main__':
    unittest.main()
