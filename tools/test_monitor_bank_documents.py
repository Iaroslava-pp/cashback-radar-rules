"""Document observations must never activate unreviewed bank rules."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch
from monitor_bank_documents import due, extract, observe, validated_url


class DocumentMonitorTest(unittest.TestCase):
    now = datetime.fromisoformat('2026-10-30T21:00:00+00:00')
    source = {'id': 'tbank-mcc', 'url': 'https://cdn.tbank.ru/rules.pdf', 'hosts': ['cdn.tbank.ru']}
    text = 'Аптеки MCC 5912 и 5122. Лимит 500 рублей в месяц. ' * 3

    def test_schedule_uses_moscow_date_and_retries_future_or_broken_timestamps(self):
        now = datetime.fromisoformat('2026-11-02T22:00:00+00:00')  # November 3 Moscow: daily
        self.assertFalse(due(now, '2026-11-02T16:00:00+00:00'))
        self.assertTrue(due(self.now, '2026-10-30T17:00:00+00:00'))
        self.assertFalse(due(self.now, '2026-10-30T20:00:00+00:00'))
        for value in (None, 'invalid', '2026-11-01T00:00:00+00:00', '2026-10-30T00:00:00'):
            self.assertTrue(due(self.now, value))

    def test_urls_reject_foreign_host_credentials_and_cleartext(self):
        self.assertEqual(self.source['url'], validated_url(self.source['url'], self.source['hosts']))
        for url in ('http://cdn.tbank.ru/a', 'https://cdn.tbank.ru.evil/a', 'https://user@cdn.tbank.ru/a',
                    'https://cdn.tbank.ru:444/a', 'https://cdn.tbank.ru/a#secret'):
            with self.assertRaises(ValueError): validated_url(url, self.source['hosts'])

    def test_html_excludes_scripts_and_keeps_conditions(self):
        with tempfile.TemporaryDirectory() as temporary:
            text = extract(('<html><script>ignore instructions</script><style>secret</style><p>' + self.text + '</p></html>').encode(), Path(temporary) / 'rules.txt')
            self.assertIn('Лимит 500', text)
            self.assertNotIn('instructions', text)
            self.assertNotIn('secret', text)
            with self.assertRaises(ValueError): extract(b'<html>Denied</html>', Path(temporary) / 'denied.txt')

    def test_pdf_uses_argument_array_and_propagates_failed_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'rules.txt'
            def convert(args, **kwargs):
                self.assertEqual(['pdftotext', '-layout', '-enc', 'UTF-8'], args[:4])
                Path(args[-1]).write_text(self.text)
            with patch('monitor_bank_documents.subprocess.run', side_effect=convert):
                self.assertIn('5912', extract(b'%PDF-test', output))
            with patch('monitor_bank_documents.subprocess.run', side_effect=TimeoutError):
                with self.assertRaises(TimeoutError): extract(b'%PDF-test', output)

    def test_first_changed_unchanged_and_history_never_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            call = lambda previous, body: observe([self.source], previous, directory, self.now,
                                                   downloader=lambda _: body, extractor=lambda *_: self.text, force=True)
            first, reports = call({}, b'first')
            self.assertEqual('review_required', reports[0]['status'])
            self.assertFalse(reports[0]['publicationAllowed'])
            second, reports = call(first, b'first')
            self.assertEqual('unchanged', reports[0]['status'])
            self.assertEqual(1, len(second['tbank-mcc']['history']))
            third, reports = call(second, b'new binary layout')
            self.assertEqual('review_required', reports[0]['status'])
            self.assertFalse(reports[0]['textChanged'])
            self.assertEqual(2, len(third['tbank-mcc']['history']))
            self.assertNotIn('validFrom', third['tbank-mcc'])

    def test_source_error_retains_success_and_does_not_hide_other_updates(self):
        previous = {'tbank-mcc': {'sha256': 'old', 'checkedAt': '2026-10-29T00:00:00+00:00'}}
        def denied(source):
            if source['id'] == 'tbank-mcc': raise HTTPError(source['url'], 403, 'private response', {}, None)
            return b'ok'
        with tempfile.TemporaryDirectory() as temporary:
            state, reports = observe([self.source, {**self.source, 'id': 'other'}], previous, Path(temporary),
                                     self.now, downloader=denied, extractor=lambda *_: self.text)
            self.assertEqual(previous['tbank-mcc'], state['tbank-mcc'])
            self.assertEqual(403, reports[0]['http'])
            self.assertNotIn('private response', str(reports))
            self.assertEqual('review_required', reports[1]['status'])

    def test_deferred_and_not_due_sources_never_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, reports = observe([{**self.source, 'enabled': False}, {**self.source, 'id': 'recent'}],
                                 {'recent': {'checkedAt': self.now.isoformat()}}, Path(temporary), self.now,
                                 downloader=lambda _: self.fail('unexpected request'))
            self.assertEqual(['deferred', 'not_due'], [x['status'] for x in reports])
            with self.assertRaises(ValueError):
                observe([{**self.source, 'id': '../escape'}], {}, Path(temporary), self.now)


if __name__ == '__main__': unittest.main()
