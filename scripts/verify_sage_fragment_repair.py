"""Verify selected native fragment observations without executing the subject."""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ID = 'cid10#fragment-resolution.4'
PREFIX = 'did-1.1/sage-resolution/fragment-search-'
SCOPE = 'Selected public recursive fragment maps only; SAGE consumer adoption, numeric client conversion and operational authority are not established.'
ROLE = 'root resolver/dereferencer library with literal example driver; not SAGE Source'


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


def decoded(value):
    require(isinstance(value, str), 'missing encoded observation')
    return json.loads(base64.b64decode(value, validate=True))


def inventory(manifest):
    ids = set()
    require([x['key'] for x in manifest['specs']] == ['did11-cr20260305', 'cid10', 'res10-crd20261001'], 'spec keys')
    for spec in manifest['specs']:
        catalog = json.loads((ROOT / 'statements' / (spec['key'] + '.json')).read_text())
        require(catalog['sha256'] == spec['sha256'] and hashlib.sha256((ROOT / 'statements' / spec['source']).read_bytes()).hexdigest() == spec['sha256'], 'frozen publication')
        ids.update(x['id'] for x in catalog['statements'])
    require(len(ids) == 486 and ID in ids, 'canonical inventory')
    return ids


def fixtures(manifest):
    source = (ROOT / 'profiles/sageresolution/fragment_search.json').read_bytes()
    require(hashlib.sha256(source).hexdigest() == manifest['fixture_sha256'], 'frozen fixture bytes')
    decoder, position, authored = json.JSONDecoder(), 1, {}
    text = source.decode()
    while True:
        while text[position].isspace() or text[position] == ',':
            position += 1
        if text[position] == ']':
            break
        item, end = decoder.raw_decode(text, position)
        literal = text[position:end]
        authored[item['name']] = {}
        for key in ['document', 'control_document']:
            matches = list(re.finditer('"' + key + r'"\s*:\s*', literal))
            require(len(matches) == 1, 'ambiguous document')
            start = matches[0].end()
            value, stop = decoder.raw_decode(literal, start)
            require(equal(value, item[key]), 'authored document')
            authored[item['name']][key] = literal[start:stop].encode()
        position = end
    data = {f['name']: f for f in json.loads(source)}
    require(len(data) == 5 and set(data) == set(manifest['case_inputs']), 'fixture inventory')
    return data, authored


def routing(out, fixture, document, index):
    q = dict(fixture['request'])
    if index == 2:
        q['input'] = 'did:example:resources#absent'
    require(out.get('capture_error', '') == '' and out['role'] == ROLE and out['operation'] == 'github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference', 'observer role')
    for name in ['application_handler', 'production', 'resource_handler']:
        require(equal(out.get(name, []), []), 'unexpected operation')
    require(equal(out['request'], {'document': {'data': base64.b64encode(document).decode(), 'media_type': 'application/did'}, 'request': q}), 'actual request')
    require(equal(decoded(out['options']), {'accept': 'application/did'}) and equal(out['resolve_inputs'], ['did:example:resources']) and len(out['resolve_options']) == 1 and equal(decoded(out['resolve_options'][0]), {'accept': 'application/did'}), 'nested input/options')
    require(equal(out['driver_inputs'], ['did:example:resources']) and len(out['driver_options']) == len(out['driver_results']) == 1, 'driver call')
    require(equal(decoded(out['driver_options'][0]), {'VersionID': '', 'VersionTime': None, 'MediaType': 'application/did', 'NoCache': False}), 'driver options')
    read = decoded(out['driver_results'][0])
    require(equal(read, {'Data': base64.b64encode(document).decode(), 'ContentType': 'application/did', 'Metadata': {}}), 'actual driver bytes')
    require(len(out['consumption']) == 1, 'consumer count')
    c = out['consumption'][0]
    require(c.get('error', '') == c.get('capture_error', '') == '' and c['operation'] == 'github.com/sage-x-project/did-go/consumer.Consumer.Consume' and c['input'] == read['Data'] and c['media_type'] == 'application/did', 'consumer input')
    require(c['require'] == c['expected'] == 'unknown' and c['strict'] is False and c['version'] == '1.1' and c['json_ld'] is False and c['dropped_terms'] is None, 'consumer configuration')
    model = json.loads(document)
    require(equal(decoded(c['model']), model) and equal(decoded(c['entries']), {}), 'consumer accessor maps')
    require(equal(decoded(out['data_model']), model) and equal(decoded(out['resolved_data_model']), model) and equal(decoded(out['entries']), {}) and equal(decoded(out['resolved_entries']), {}) and equal(decoded(out['resolved_metadata']), {'contentType': 'application/did'}), 'same-call immutable document')
    result = out['result']
    require(result.get('native') is None and result.get('exchange') is None and equal(result['content_metadata'], {}), 'native result scope')
    if index == 2:
        error = result['metadata'].get('error', {})
        require(error.get('type') == 'https://www.w3.org/ns/did#NOT_FOUND' and isinstance(error.get('detail'), str) and bool(error['detail']), 'absent fragment refusal')
        require(result['has_content'] is False and decoded(result['raw']) is None and result.get('returned_id', '') == '' and result.get('snapshot') is None and result.get('content_kind', '') == '', 'absent fragment content')
    else:
        expected = fixture['expected_content']
        require(result['has_content'] is True and result['content_kind'] == 'map' and result['returned_id'] == expected['id'] and equal(result['metadata'], {'contentType': 'application/ld+json'}), 'selected map attribution')
        require(equal(result['snapshot'], expected) and equal(decoded(result['raw']), expected), 'selected map contents')


def verify(evidence, observer, manifest):
    require(bool(observer.strip()) and evidence['scope'] == SCOPE and evidence['runtime_results_merged'] is False, 'scope')
    ids = inventory(manifest)
    fixed, authored = fixtures(manifest)
    report, raw = evidence['report'], evidence['raw']
    subject = {k: manifest['subject'][k] for k in ['name', 'version', 'revision']}
    require(equal(report['subject'], subject) and equal(raw['subject'], subject) and report['inspector']['revision'] == observer and raw['profile'] == report['profile'] == 'did-1.1' and equal(report['specs'], manifest['specs']), 'identity')
    require(equal(report['totals'], {'statements': 486, 'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'NOT_APPLICABLE': 0, 'NOT_SUPPORTED': 0, 'NOT_RUN': 485}), 'totals')
    cases = {PREFIX + name for name in fixed}
    require(len(raw['cases']) == 5 and {c['case'] for c in raw['cases']} == cases, 'case inventory')
    for case in raw['cases']:
        name = case['case'][len(PREFIX):]
        f = fixed[name]
        require(case['statements'] == [ID] and len(case['observations']) == 1, 'statement attribution')
        o = case['observations'][0]
        expected_input = {k: f[k] for k in ['name', 'document', 'control_document', 'expected_content', 'request']}
        require(o['statement'] == ID and o['verdict'] == 'PASS' and equal(json.loads(o['input']), expected_input) and hashlib.sha256(o['input'].encode()).hexdigest() == manifest['case_inputs'][name], 'frozen input and verdict')
        values = json.loads(o['observed'])
        require(isinstance(values, list) and len(values) == 3, 'actual calls')
        for i, out in enumerate(values):
            routing(out, f, authored[name]['control_document' if i == 1 else 'document'], i)
    require(len(report['statements']) == 486 and {x['id'] for x in report['statements']} == ids, 'canonical report')
    for row in report['statements']:
        require(row['verdict'] == ('PASS' if row['id'] == ID else 'NOT_RUN') and set(row.get('cases', [])) == (cases if row['id'] == ID else set()), 'statement/case attribution')
    require(len(report['cases']) == 5 and {x['id'] for x in report['cases']} == cases, 'report cases')
    require(all(x['verdict'] == 'PASS' and x['statements'] == [ID] and type(x['observations']) is int and x['observations'] == 1 for x in report['cases']), 'report case verdicts')
    require(isinstance(report['not_run'], list) and len(report['not_run']) == 485 and set(report['not_run']) == ids - {ID}, 'not-run inventory')
    return {'subject': subject, 'observer': observer, 'runtime_results_merged': False, 'cases': 5, 'actual_native_calls': 15, 'selected_PASS': [ID], 'NOT_RUN': 485}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--observer', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'docs/sage-fragment-repair.json').read_text())
    result = verify(json.loads(args.evidence.read_text()), args.observer, manifest)
    with args.out.open('x') as out:
        out.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
