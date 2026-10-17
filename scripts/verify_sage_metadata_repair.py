"""Check one independently pinned metadata observation, without executing Go."""
import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

ID = 'res10-crd20261001#resolver-architectures-proxied.2'
ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def equal(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b))
    return a == b


def inventory(manifest):
    result = set()
    require([x['key'] for x in manifest['specs']] == ['did11-cr20260305', 'cid10', 'res10-crd20261001'], 'spec keys')
    for spec in manifest['specs']:
        catalog = json.loads((ROOT / 'statements' / (spec['key'] + '.json')).read_text())
        require(catalog['sha256'] == spec['sha256'] and hashlib.sha256((ROOT / 'statements' / spec['source']).read_bytes()).hexdigest() == spec['sha256'], 'frozen source')
        result.update(x['id'] for x in catalog['statements'])
    require(len(result) == 486 and ID in result, 'canonical inventory')
    return result


def decoded(value):
    require(isinstance(value, str), 'encoded observation type')
    return json.loads(base64.b64decode(value, validate=True))


def verify(evidence, observer, manifest, original):
    require(evidence['runtime_results_merged'] is False, 'merged historical results')
    report, raw = evidence['report'], evidence['raw']
    require(report['inspector']['revision'] == observer and bool(observer.strip()), 'observer identity')
    require(report['subject'] == raw['subject'] == {k: manifest['subject'][k] for k in ['name', 'version', 'revision']}, 'subject identity')
    require(report['specs'] == manifest['specs'], 'specification identity')
    require(raw['profile'] == report['profile'] == 'did-1.1', 'profile')
    require(len(raw['cases']) == 1, 'case count')
    case = raw['cases'][0]
    require(case['case'] == manifest['case'] and case['statements'] == [ID] and len(case['observations']) == 1, 'case attribution')
    observation = case['observations'][0]
    require(observation['statement'] == ID and observation['verdict'] == 'PASS', 'statement verdict')
    require(observation['input'] == original and hashlib.sha256(original.encode()).hexdigest() == manifest['input_sha256'], 'literal input')
    expected_request = json.loads(original)['Request']
    reply = json.loads(base64.b64decode(expected_request['reply'], validate=True))
    actual = json.loads(observation['observed'])
    require(equal(actual['request'], expected_request), 'actual request')
    require(actual['operation'] == 'github.com/sage-x-project/did-go/resolution/universal.Client.resolve', 'actual operation')
    require(actual['server_tls'] is True and type(actual['server_calls']) is int and actual['server_calls'] == 1 and isinstance(actual['wire'], list) and isinstance(actual['consumer'], list) and len(actual['wire']) == len(actual['consumer']) == 1 and equal(actual['native'], []), 'actual TLS call')
    require(actual['server_role'] == 'controlled client response fixture; not SAGE server output', 'server role')
    endpoint = urlsplit(actual['endpoint'])
    require(endpoint.scheme == 'https' and endpoint.port is not None and 0 < endpoint.port < 65536 and '?' not in actual['endpoint'] and '#' not in actual['endpoint'] and ipaddress.ip_address(endpoint.hostname).is_loopback and endpoint.path == '/1.0/identifiers/' and not endpoint.query and not endpoint.fragment and endpoint.username is None, 'owned endpoint')
    wire = actual['wire'][0]
    require(wire['method'] == 'GET' and wire['url'] == actual['endpoint'] + expected_request['request']['input'] and wire['accept'] == 'application/did' and wire['body'] is None and wire['content_type'] == '' and wire.get('capture_error', '') == '', 'wire request')
    consumer = actual['consumer'][0]
    require(consumer.get('error', '') == '' and consumer.get('capture_error', '') == '', 'consumer error')
    require(consumer['operation'] == 'github.com/sage-x-project/did-go/consumer.Consumer.Consume' and consumer['media_type'] == 'application/did' and consumer['require'] == consumer['expected'] == 'unknown' and consumer['strict'] is False and consumer['version'] == '1.1' and consumer['json_ld'] is False and (consumer['dropped_terms'] is None or equal(consumer['dropped_terms'], [])), 'consumer attribution')
    require(equal(decoded(consumer['input']), reply['didDocument']) and equal(decoded(consumer['model']), reply['didDocument']) and equal(decoded(consumer['entries']), {}), 'consumer accessor maps')
    result = actual['result']
    require(result['has_content'] is True and result['returned_id'] == expected_request['request']['input'] and result['content_kind'] == 'document' and equal(result['snapshot'], reply['didDocument']) and equal(decoded(result['raw']), reply['didDocument']), 'document result')
    require(equal(result['metadata'], reply['didResolutionMetadata']) and equal(result['content_metadata'], reply['didDocumentMetadata']), 'transparent metadata')
    require(result['content_metadata'].get('deactivated') is False, 'explicit false')
    require(equal(report['totals'], {'statements': 486, 'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'NOT_APPLICABLE': 0, 'NOT_SUPPORTED': 0, 'NOT_RUN': 485}), 'separate report totals')
    statements = report['statements']
    ids = inventory(manifest)
    require(len(statements) == 486 and {x['id'] for x in statements} == ids, 'canonical statements')
    require(len(report['cases']) == 1 and report['cases'][0]['id'] == manifest['case'] and report['cases'][0]['statements'] == [ID] and report['cases'][0]['verdict'] == 'PASS' and type(report['cases'][0]['observations']) is int and report['cases'][0]['observations'] == 1, 'report case')
    require(isinstance(report['not_run'], list) and len(report['not_run']) == 485 and set(report['not_run']) == ids - {ID}, 'not-run inventory')
    require(all(x['verdict'] == ('PASS' if x['id'] == ID else 'NOT_RUN') for x in statements), 'unobserved statements')
    return {'subject': report['subject'], 'observer': observer, 'runtime_results_merged': False, 'selected_PASS': [ID], 'NOT_RUN': 485, 'actual_TLS_calls': 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--observer', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'docs/sage-metadata-repair.json').read_text())
    original = (ROOT / 'scripts/testdata/sage-metadata-input.json').read_text().rstrip('\n')
    result = verify(json.loads(args.evidence.read_text()), args.observer, manifest, original)
    with args.out.open('x') as destination:
        destination.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
