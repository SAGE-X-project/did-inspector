"""Independently check the separate reviewed-source primary-resource URL observations."""
import argparse
import base64
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

import verify_sage_fragment_repair as common

ROOT = Path(__file__).resolve().parents[1]
IDS = ['res10-crd20261001#dereferencing-algorithm-resource.11']
CASE = 'did-1.1/sage-resolution/repaired-primary-resource-url'
SCOPE = 'Selected reviewed primary resource URL adjustment only; arbitrary handler media fragments, SAGE consumer adoption and operational authority are not established.'
PACKAGES = ['dereferencer', 'relyingparty', 'did', 'document', 'internal/multiformats', 'internal/wire', 'representation', 'resolution', 'spec', 'vm']
require, equal, decoded = common.require, common.equal, common.decoded


def request(m):
    return {'module': m['module'], 'version': m['version'], 'packages': PACKAGES, 'diagnostics': None}



def fixtures(m):
    data = (ROOT / 'profiles/sageresolution/url_roles.json').read_bytes()
    require(hashlib.sha256(data).hexdigest() == m['fixture_sha256'], 'original fixture source')
    decoder, out = json.JSONDecoder(), []
    text = data.decode()
    matches = list(re.finditer(r'"handlers"\s*:\s*\[', text))
    require(len(matches) == 1, 'original handler collection')
    position = matches[0].end()
    while True:
        while text[position].isspace() or text[position] == ',':
            position += 1
        if text[position] == ']':
            break
        item, end = decoder.raw_decode(text, position)
        literal = text[position:end]
        matches = list(re.finditer(r'"document"\s*:\s*', literal))
        require(len(matches) == 1, 'ambiguous original document')
        start = matches[0].end()
        document, stop = decoder.raw_decode(literal, start)
        require(equal(document, item['document']), 'original document bytes')
        out.append((item, literal[start:stop].encode()))
        position = end
    require([x[0]['name'] for x in out] == ['path', 'path-fragment', 'empty-fragment', 'query-fragment', 'path-query-fragment', 'percent-fragment', 'document-fragment'], 'seven original fixtures')
    return out

def source(v, m):
    require(equal(v['request'], request(m)) and v['module'] == m['module'] and v['version'] == m['version'] and v['sum'] == m['sum'] and v['replaced'] is False, 'source identity')
    require(v['operation'] == 'debug.ReadBuildInfo + local go env + module cache/ZIP byte capture' and v['compiler'] == v['environment_compiler'] == 'go1.26.8' and equal(v['diagnostics'], []), 'source capture/compiler')
    archive = base64.b64decode(v['archive'], validate=True)
    require(len(archive) <= 64 * 1024 * 1024, 'bounded archive')
    prefix = m['module'] + '@' + m['version'] + '/'
    all_files, selected = {}, {}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for entry in z.infolist():
            require(entry.filename.startswith(prefix) and not entry.is_dir() and entry.file_size < 16 * 1024 * 1024 and '..' not in entry.filename.split('/'), 'archive path/size')
            name = entry.filename[len(prefix):]
            require(name not in all_files, 'duplicate archive entry')
            all_files[name] = z.read(entry)
            require(sum(map(len, all_files.values())) <= 64 * 1024 * 1024, 'archive total size')
            if str(Path(name).parent) in PACKAGES and name.endswith('.go') and not name.endswith('_test.go'):
                selected[name] = all_files[name]
    canonical = ''.join(hashlib.sha256(all_files[n]).hexdigest() + '  ' + prefix + n + '\n' for n in sorted(all_files)).encode()
    require('h1:' + base64.b64encode(hashlib.sha256(canonical).digest()).decode() == m['sum'], 'independent module ZIP sum')
    require(selected.keys() == v['files'].keys() == m['source_files'].keys(), 'complete selected source set')
    for name, content in selected.items():
        require(content == base64.b64decode(v['files'][name], validate=True) and hashlib.sha256(content).hexdigest() == m['source_files'][name], 'reviewed source/cache/ZIP bytes')



def audit(v, m):
    a = v['audit']
    w = json.loads((ROOT / 'profiles/sageresolution/url_roles_witness.json').read_text())
    require(equal(a['roots'], w['roots']) and equal(a['roles'], w['roles']) and equal(a['call_paths'], w['call_paths']) and equal(a['unknown'], []), 'typed closed context')
    require(len(a['steps']) == 2 and equal(a['steps'][0], {'kind': w['steps'][0]['kind'], 'correct': True, 'expressions': ['u.WithoutFragment()']}) and equal(a['steps'][1], w['steps'][1]), 'typed adjustment and extraction prerequisite')
    frames = a['frames']
    names = w['roots'] + [m['module'] + '/did.(' + m['module'] + '/did.DIDURL).WithoutFragment', m['module'] + '/dereferencer.(*' + m['module'] + '/dereferencer.Dereferencer).fragment']
    require(isinstance(frames, dict) and all(re.fullmatch('[0-9a-f]{64}', h) for h in frames.values()) and all(frames.get(n) == w['frames'][n] for n in names), 'twelve critical reviewed function frames')
    edge = [names[1], names[-2]]
    require(equal(v['edges'], [edge]), 'actual primary URL adjustment call edge')


def routing(v, f, document):
    require(v.get('capture_error', '') == '' and v['role'] == common.ROLE and v['operation'] == 'github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference', 'native role')
    for k in ['application_handler', 'production']:
        require(equal(v.get(k, []), []), 'unexpected production/transport operation')
    body = base64.b64encode(document).decode()
    require(equal(v['request'], {'document': {'data': body, 'media_type': 'application/did'}, 'request': f['request'], 'observe_resource_handler': True}), 'literal actual request')
    options = {'accept': 'application/did'}
    nested = dict(options)
    if f['parts']['has_query']:
        nested['relativeRef'] = 'next'
    require(equal(decoded(v['options']), options) and equal(v['resolve_inputs'], ['did:example:resources']) and len(v['resolve_options']) == 1 and equal(decoded(v['resolve_options'][0]), nested), 'actual resolution input/options')
    require(equal(v['driver_inputs'], ['did:example:resources']) and len(v['driver_options']) == len(v['driver_results']) == 1, 'single literal driver read')
    require(equal(decoded(v['driver_options'][0]), {'VersionID': '', 'VersionTime': None, 'MediaType': 'application/did', 'NoCache': False}), 'driver options')
    require(equal(decoded(v['driver_results'][0]), {'Data': body, 'ContentType': 'application/did', 'Metadata': {}}), 'driver bytes')
    require(len(v['consumption']) == 1, 'same-call consumer count')
    c = v['consumption'][0]
    require(c['operation'] == 'github.com/sage-x-project/did-go/consumer.Consumer.Consume' and c['input'] == body and c['media_type'] == 'application/did' and c['require'] == c['expected'] == 'unknown' and c['version'] == '1.1' and c['strict'] is False and c['json_ld'] is False and c['dropped_terms'] is None and c.get('error', '') == c.get('capture_error', '') == '', 'consumer boundary')
    require(equal(decoded(c['model']), f['document']) and equal(decoded(c['entries']), {}), 'original consumer model')
    for k in ['data_model', 'resolved_data_model']:
        require(equal(decoded(v[k]), f['document']), 'original resolved model')
    for k in ['entries', 'resolved_entries']:
        require(equal(decoded(v[k]), {}), 'representation entries')
    require(equal(decoded(v['resolved_metadata']), {'contentType': 'application/did'}), 'resolution metadata')
    handlers = v.get('resource_handler', [])
    require(len(handlers) == f['handler_calls'], 'actual handler count')
    for h in handlers:
        require(h['Operation'] == 'github.com/sage-x-project/did-go/dereferencer.ResourceHandler' and h['Role'] == 'literal passive resource handler; records actual values and returns unhandled' and h.get('capture_error', '') == '', 'passive handler boundary')
        require(equal(h['URL'], f['adjusted']), 'literal fragment-free actual handler URL')
        require(equal(decoded(h['Options']), options) and equal(decoded(h['Model']), f['document']) and equal(decoded(h['Entries']), {}) and equal(decoded(h['Metadata']), {'contentType': 'application/did'}), 'same-call handler document/options')
    result = v['result']
    require(result.get('native') is None and result.get('exchange') is None and equal(result['content_metadata'], {}), 'native content attribution')
    raw = decoded(result['raw'])
    if f['diagnostic_error']:
        # Retain diagnostic refusal; it does not establish URL adjustment.
        require(result['has_content'] is False and raw is None and result.get('snapshot') is None and result.get('content_kind', '') == result.get('returned_id', '') == '' and result['metadata']['error']['type'] == f['diagnostic_error'], 'unchanged diagnostic refusal')
    else:
        require(result['has_content'] is True and result['content_kind'] == f['expected_kind'] and equal(raw, f['expected_content']) and equal(result.get('snapshot'), f['expected_content']) and result.get('returned_id') == f['expected_content']['id'] and equal(result['metadata'], {'contentType': 'application/ld+json'}), 'original document fragment control')


def verify(e, observer, m):
    require(m['schema'] == 1 and m['scope'] == 'selected-reviewed-primary-resource-url' and m['runtime_results_merged'] is False, 'manifest scope')
    require(bool(observer.strip()) and e['scope'] == SCOPE and e['runtime_results_merged'] is False, 'scope')
    ids = common.inventory(m)
    fs = fixtures(m)
    report, raw = e['report'], e['raw']
    subject = {k: m['subject'][k] for k in ['name', 'version', 'revision']}
    require(equal(report['subject'], subject) and equal(raw['subject'], subject) and report['inspector']['revision'] == observer and report['profile'] == raw['profile'] == 'did-1.1' and equal(report['specs'], m['specs']), 'actual observer/subject identity')
    require(equal(report['totals'], {'statements': 486, 'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'NOT_SUPPORTED': 0, 'NOT_APPLICABLE': 0, 'NOT_RUN': 485}), 'single-clause totals')
    require(len(raw['cases']) == 1 and raw['cases'][0]['case'] == CASE and raw['cases'][0]['statements'] == IDS, 'selected case')
    observations = raw['cases'][0]['observations']
    require(len(observations) == 1 and observations[0]['statement'] == IDS[0], 'one observation')
    o = observations[0]
    require(o['verdict'] == 'PASS' and equal(json.loads(o['input']), request(m)), 'source request/verdict')
    v = json.loads(o['observed'])
    require(v.get('analysis_error', '') == '' and len(v['runtime']) == 7, 'complete source/runtime evidence')
    source(v['source'], m)
    audit(v, m)
    for (f, document), out in zip(fs, v['runtime']):
        routing(out, f, document)
    require(sum(len(x.get('resource_handler', [])) for x in v['runtime']) == 6, 'six direct handler captures')
    require(len(report['statements']) == 486 and {s['id'] for s in report['statements']} == ids, 'canonical statements')
    for row in report['statements']:
        require(row['verdict'] == ('PASS' if row['id'] in IDS else 'NOT_RUN') and equal(row.get('cases', []), [CASE] if row['id'] in IDS else []), 'clause/case attribution')
    require(len(report['cases']) == 1 and report['cases'][0]['id'] == CASE and report['cases'][0]['verdict'] == 'PASS' and report['cases'][0]['statements'] == IDS and type(report['cases'][0]['observations']) is int and report['cases'][0]['observations'] == 1, 'case result')
    require(len(report['not_run']) == 485 and set(report['not_run']) == ids - set(IDS), 'remaining not-run')
    return {'subject': subject, 'observer': observer, 'runtime_results_merged': False, 'cases': 1, 'source_captures': 1, 'actual_native_calls': 7, 'passive_handler_captures': 6, 'selected_PASS': IDS, 'NOT_RUN': 485}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--observer', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    m = json.loads((ROOT / 'profiles/sageresolution/resource_repair.json').read_text())
    result = verify(json.loads(args.evidence.read_text()), args.observer, m)
    with args.out.open('x') as out:
        out.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
