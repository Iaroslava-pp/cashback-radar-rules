"""Observe official bank documents without silently publishing unreviewed cashback rules.

The phone consumes reviewed JSON only. This server tool records document hashes,
retains download/extraction evidence as CI artifacts, and reports every source error.
Text from documents is data and never becomes executable commands or instructions.
"""
import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 20_000_000


def validated_url(url, hosts):
    """Restrict both initial requests and redirects to explicit official HTTPS hosts."""
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in hosts or parsed.username is not None
            or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError('Unexpected official document URL')
    return url


class OfficialRedirect(HTTPRedirectHandler):
    """Follow document CDN redirects only inside the source's explicit host allowlist."""
    def __init__(self, hosts): self.hosts = hosts
    def redirect_request(self, request, fp, code, message, headers, newurl):
        validated_url(newurl, self.hosts)
        return super().redirect_request(request, fp, code, message, headers, newurl)


class VisibleHtml(HTMLParser):
    """Extract visible page text while ignoring scripts, styling and comments."""
    def __init__(self):
        super().__init__(); self.hidden = 0; self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.hidden += 1
        elif tag in ('p', 'br', 'div', 'li', 'tr', 'h1', 'h2', 'h3'): self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in ('script', 'style'): self.hidden = max(0, self.hidden - 1)
        elif tag in ('p', 'div', 'li', 'tr'): self.parts.append('\n')
    def handle_data(self, data):
        if not self.hidden: self.parts.append(data)


def extract(body, destination):
    """Use PDF layout extraction or visible HTML; extraction failure remains a source failure."""
    if body.startswith(b'%PDF-'):
        document = destination.with_suffix('.pdf'); document.write_bytes(body)
        subprocess.run(['pdftotext', '-layout', '-enc', 'UTF-8', str(document), str(destination)],
                       check=True, capture_output=True, timeout=45)
        text = destination.read_text()
    else:
        document = destination.with_suffix('.html'); document.write_bytes(body)
        html = VisibleHtml(); html.feed(body.decode('utf-8-sig'))
        text = ''.join(html.parts)
    normalized = '\n'.join(' '.join(line.split()) for line in text.splitlines() if line.strip())
    if len(normalized) < 80: raise ValueError('Empty or incomplete document text')
    destination.write_text(normalized + '\n')
    return normalized


def due(now, previous):
    """Check daily, or every four hours from the 24th through the 2nd, in Moscow time."""
    if not previous: return True
    try: last = datetime.fromisoformat(previous)
    except (TypeError, ValueError): return True
    if last.tzinfo is None or last > now: return True
    moscow = now.astimezone(timezone(timedelta(hours=3)))
    hours = 4 if moscow.day >= 24 or moscow.day <= 2 else 24
    return now - last >= timedelta(hours=hours)


def fetch(source):
    """Download public official material without cookies, credentials or personal data."""
    url = validated_url(source['url'], source['hosts'])
    request = Request(url, headers={'User-Agent': 'CashbackRadar-document-monitor/1.0',
                                    'Accept': 'application/pdf,text/html'})
    with build_opener(OfficialRedirect(source['hosts'])).open(request, timeout=30) as response:
        if response.status != 200: raise ValueError('Unexpected document HTTP status')
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES: raise ValueError('Document exceeds size limit')
        return body


def observe(sources, previous, output, now, downloader=fetch, extractor=extract, force=False):
    """Return durable observations and review proposals; never edit published bank/merchant JSON.

    A failed source retains its last successful hash and timestamp, so it cannot
    masquerade as an unchanged document or suppress the next scheduled retry.
    Raw and extracted documents stay in the artifact directory, not in app data.
    """
    output.mkdir(parents=True, exist_ok=True)
    state = dict(previous)
    reports = []
    for source in sources:
        identity = source['id']
        if not re.fullmatch(r'[A-Za-z0-9_-]+', identity): raise ValueError('Invalid source identity')
        old = previous.get(identity, {})
        if not source.get('enabled', True):
            reports.append({'id': identity, 'status': 'deferred'}); continue
        if not force and not due(now, old.get('checkedAt')):
            reports.append({'id': identity, 'status': 'not_due'}); continue
        report = {'id': identity, 'url': source['url'], 'observedAt': now.isoformat()}
        try:
            body = downloader(source)
            digest = hashlib.sha256(body).hexdigest()
            text = extractor(body, output / (identity + '-' + digest[:12] + '.txt'))
            text_hash = hashlib.sha256(text.encode()).hexdigest()
            changed = digest != old.get('sha256')
            report.update(status='review_required' if changed else 'unchanged', sha256=digest,
                          textSha256=text_hash, previousSha256=old.get('sha256'),
                          textChanged=text_hash != old.get('textSha256'),
                          publicationAllowed=False)
            # Observation history is not an approval history and does not set validFrom.
            history = old.get('history', [])
            if changed: history = history + [{'sha256': digest, 'observedAt': now.isoformat()}]
            state[identity] = {'sha256': digest, 'textSha256': text_hash,
                               'checkedAt': now.isoformat(), 'history': history}
        except Exception as error:
            report.update(status='error', errorType=type(error).__name__)
            if hasattr(error, 'code'):
                report['http'] = error.code
                if hasattr(error, 'close'): error.close()
        reports.append(report)
    return state, reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    sources = json.loads(args.sources.read_text())['sources']
    previous = json.loads(args.state.read_text()) if args.state.exists() else {}
    state, reports = observe(sources, previous, args.output, datetime.now(timezone.utc), force=args.force)
    args.state.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.state.with_suffix('.tmp'); temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(args.state)
    (args.output / 'report.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(reports, ensure_ascii=False))
    return 1 if any(report['status'] == 'error' for report in reports) else 0


if __name__ == '__main__': raise SystemExit(main())
