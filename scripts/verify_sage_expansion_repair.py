"""Independently check the separate reviewed-source expansion observations."""
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
IDS = ['res10-crd20261001#resolving-algorithm.28', 'res10-crd20261001#resolving-algorithm.29']
CASE = 'did-1.1/sage-resolution/repaired-relative-expansion'
SCOPE = 'Selected reviewed public relative identifier expansion only; full URI semantics, SAGE consumer adoption and operational authority are not established.'
PACKAGES = ['resolver', 'method', 'did', 'document', 'internal/multiformats', 'representation', 'resolution', 'spec', 'vm']
require, equal, decoded = common.require, common.equal, common.decoded


def request(m):
    return {'module': m['module'], 'version': m['version'], 'packages': PACKAGES, 'diagnostics': None}


def fixtures(m):
    data = (ROOT / 'profiles/sageresolution/expansion_source.json').read_bytes()
    require(hashlib.sha256(data).hexdigest() == m['fixture_sha256'], 'original fixture source')
    decoder, position, out = json.JSONDecoder(), 1, []
    text = data.decode()
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
    require([x[0]['name'] for x in out] == ['absent', 'disabled', 'nested-extras', 'root-relocated', 'empty-collections'], 'five original fixtures')
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
    witness = json.loads((ROOT / 'profiles/sageresolution/expansion_source_witness.json').read_text())
    roles = dict(witness['roles'], method_extensions='true', service_extensions='true')
    require(equal(a['roots'], witness['roots']) and equal(a['roles'], roles) and equal(a['call_paths'], witness['call_paths']) and equal(a['unknown'], []), 'typed closed context')
    require(len(a['steps']) == 2 and [s['kind'] for s in a['steps']] == ['expansion-enabled-condition', 'complete-extension-traversal'] and all(s['correct'] is True for s in a['steps']), 'typed guard/traversal')
    require(a['steps'][0]['expressions'] == ['opts.ExpandRelativeURLs'] and a['steps'][1]['expressions'] == ['typed Method.Extra read: true', 'typed Service.Extra read: true'], 'typed field evidence')
    pairs = [('expand', 'expandJSONMap'), ('expandMethod', 'expandJSONMap'), ('expandJSONMap', 'absoluteString'), ('expandJSONMap', 'expandJSONValue'), ('expandJSONValue', 'expandJSONMap'), ('expandJSONValue', 'expandJSONValue')]
    edges = [[m['module'] + '/resolver.' + n for n in pair] for pair in pairs]
    require(equal(v['edges'], edges), 'new recursive public map edges')
    require(isinstance(a['frames'], dict) and len(a['frames']) >= len(witness['frames']) and all(re.fullmatch('[0-9a-f]{64}', h) for h in a['frames'].values()), 'closed function frames')
    require(all(n in a['frames'] for edge in edges for n in edge), 'recursive frames')


def routing(v, f, document):
    require(v.get('capture_error', '') == '' and v['role'] == common.ROLE and v['operation'] == 'github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve', 'native role')
    for k in ['application_handler', 'production', 'resource_handler']:
        require(equal(v.get(k, []), []), 'unexpected production/transport operation')
    body = base64.b64encode(document).decode()
    require(equal(v['request'], {'document': {'data': body, 'media_type': 'application/did'}, 'request': f['request']}), 'literal actual request')
    options = {'accept': 'application/did'}
    enabled = f['request'].get('options', {}).get('expandRelativeUrls') is True
    if enabled:
        options['expandRelativeUrls'] = True
    require(equal(decoded(v['options']), options) and equal(v['resolve_inputs'], ['did:example:123']) and len(v['resolve_options']) == 1 and equal(decoded(v['resolve_options'][0]), options), 'actual resolution input/options')
    require(equal(v['driver_inputs'], ['did:example:123']) and len(v['driver_options']) == len(v['driver_results']) == 1, 'single literal driver read')
    require(equal(decoded(v['driver_options'][0]), {'VersionID': '', 'VersionTime': None, 'MediaType': 'application/did', 'NoCache': False}), 'driver options')
    require(equal(decoded(v['driver_results'][0]), {'Data': body, 'ContentType': 'application/did', 'Metadata': {}}), 'driver bytes')
    require(len(v['consumption']) == 1, 'same-call consumer count')
    c = v['consumption'][0]
    require(c['operation'] == 'github.com/sage-x-project/did-go/consumer.Consumer.Consume' and c['input'] == body and c['media_type'] == 'application/did' and c['require'] == c['expected'] == 'unknown' and c['version'] == '1.1' and c['strict'] is False and c['json_ld'] is False and c['dropped_terms'] is None and c.get('error', '') == c.get('capture_error', '') == '', 'consumer boundary')
    require(equal(decoded(c['model']), f['document']) and equal(decoded(c['entries']), {}), 'pre-expansion model')
    for k in ['data_model', 'resolved_data_model']:
        require(equal(decoded(v[k]), f['expected']), 'complete independent expanded model')
    for k in ['entries', 'resolved_entries']:
        require(equal(decoded(v[k]), {}), 'representation entries')
    require(equal(decoded(v['resolved_metadata']), {'contentType': 'application/did'}), 'resolution metadata')
    r = v['result']
    require(r.get('native') is None and r.get('exchange') is None and r['has_content'] is True and r['returned_id'] == 'did:example:123' and r['content_kind'] == 'document', 'native content attribution')
    require(equal(r['metadata'], {'contentType': 'application/did'}) and equal(r['content_metadata'], {}) and equal(r['snapshot'], f['expected']), 'accessor snapshot and metadata')
    wire = decoded(r['raw'])
    if enabled:
        require(wire.pop('@context', None) == 'https://www.w3.org/ns/did/v1.1', 'expanded wire context')
    require(equal(wire, f['expected']), 'actual produced wire model')


def verify(e, observer, m):
    require(m['schema'] == 1 and m['scope'] == 'selected-reviewed-relative-expansion' and m['runtime_results_merged'] is False, 'manifest scope')
    require(bool(observer.strip()) and e['scope'] == SCOPE and e['runtime_results_merged'] is False, 'scope')
    ids = common.inventory(m)
    fs = fixtures(m)
    report, raw = e['report'], e['raw']
    subject = {k: m['subject'][k] for k in ['name', 'version', 'revision']}
    require(equal(report['subject'], subject) and equal(raw['subject'], subject) and report['inspector']['revision'] == observer and report['profile'] == raw['profile'] == 'did-1.1' and equal(report['specs'], m['specs']), 'actual observer/subject identity')
    require(equal(report['totals'], {'statements': 486, 'PASS': 2, 'FAIL': 0, 'ERROR': 0, 'NOT_SUPPORTED': 0, 'NOT_APPLICABLE': 0, 'NOT_RUN': 484}), 'two-clause totals')
    require(len(raw['cases']) == 1 and raw['cases'][0]['case'] == CASE and raw['cases'][0]['statements'] == IDS, 'selected case')
    observations = raw['cases'][0]['observations']
    require(len(observations) == 2 and [x['statement'] for x in observations] == IDS, 'two observations')
    prior = None
    for o in observations:
        require(o['verdict'] == 'PASS' and equal(json.loads(o['input']), request(m)), 'source request/verdict')
        v = json.loads(o['observed'])
        require(v.get('analysis_error', '') == '' and len(v['runtime']) == 5, 'complete source/runtime evidence')
        if prior is not None:
            require(equal(v, prior), 'same proof shared by both clauses')
        prior = v
        source(v['source'], m)
        audit(v, m)
        expected_items = []
        for (f, document), out in zip(fs, v['runtime']):
            routing(out, f, document)
            for path in f['extension_paths']:
                original, wanted = f['document'], f['expected']
                for part in path:
                    original = original[int(part)] if isinstance(original, list) else original[part]
                    wanted = wanted[int(part)] if isinstance(wanted, list) else wanted[part]
                require(type(original) is str and original.startswith('#') and len(original) > 1 and wanted == 'did:example:123' + original, 'qualifying literal object id')
                expected_items.append({'path': path, 'original': original, 'expected': wanted, 'observed': wanted, 'qualifies': True})
        require(len(expected_items) == 5 and equal(v['items'], expected_items), 'five per-item predicates/results')
    require(len(report['statements']) == 486 and {s['id'] for s in report['statements']} == ids, 'canonical statements')
    for row in report['statements']:
        require(row['verdict'] == ('PASS' if row['id'] in IDS else 'NOT_RUN') and equal(row.get('cases', []), [CASE] if row['id'] in IDS else []), 'clause/case attribution')
    require(len(report['cases']) == 1 and report['cases'][0]['id'] == CASE and report['cases'][0]['verdict'] == 'PASS' and report['cases'][0]['statements'] == IDS and type(report['cases'][0]['observations']) is int and report['cases'][0]['observations'] == 2, 'case result')
    require(len(report['not_run']) == 484 and set(report['not_run']) == ids - set(IDS), 'remaining not-run')
    return {'subject': subject, 'observer': observer, 'runtime_results_merged': False, 'cases': 1, 'source_captures': 1, 'actual_native_calls': 5, 'selected_PASS': IDS, 'NOT_RUN': 484}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--observer', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    m = json.loads((ROOT / 'profiles/sageresolution/expansion_repair.json').read_text())
    result = verify(json.loads(args.evidence.read_text()), args.observer, m)
    with args.out.open('x') as out:
        out.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
