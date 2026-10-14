import base64
import copy
import json
import os
from pathlib import Path
import unittest
import zipfile
import check_sage_integer_source as checker

class IntegerSourceLiteralTests(unittest.TestCase):
    def test_canonical_archive_digest(self):
        w=json.loads((checker.REPO/'profiles/sageresolution/integer_source_witness.json').read_text())
        z=(checker.REPO/'checks/sourcearith/testdata/did-go-pinned.zip').read_bytes()
        digest,files=checker.archive_files(base64.b64encode(z),w['module']+'@'+w['version'])
        self.assertEqual(digest,w['sum']);self.assertEqual(len(files),16)

@unittest.skipUnless(os.environ.get('SAGE_BATCH_REPORT_DIR'),'actual adapter report evidence')
class ActualIntegerSourceTests(unittest.TestCase):
    def setUp(self):
        r=Path(os.environ['SAGE_BATCH_REPORT_DIR']);self.raw=json.loads((r/'resolution-did-1.1-raw.json').read_text());self.report=json.loads((r/'resolution-did-1.1.json').read_text())
    def test_actual_source_witness(self):self.assertEqual(checker.verify_integer_source(self.raw,self.report),set(checker.IDS))
    def mutate(self,change,reject=True):
        raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case']==checker.CASE)
        v=json.loads(c['observations'][0]['observed']);change(v)
        for o in c['observations']:o['observed']=json.dumps(v)
        if reject:
            with self.assertRaises((AssertionError,KeyError,TypeError,ValueError,zipfile.BadZipFile)):checker.verify_integer_source(raw,self.report)
        else:self.assertEqual(checker.verify_integer_source(raw,self.report),set(checker.IDS))
    def test_identity_source_and_typed_witness_changes_rejected(self):
        for change in [lambda v:v['source'].update(version='wrong'),lambda v:v['source'].update(sum='h1:wrong'),lambda v:v['source'].update(replaced=True),lambda v:v['source'].update(environment_compiler='go1.25.0'),lambda v:v['source']['files'].update({'internal/multiformats/base.go':'e30='}),lambda v:v['source']['files'].pop('internal/multiformats/base.go'),lambda v:v['source'].update(archive=base64.b64encode(b'bad').decode()),lambda v:v['call_paths'][0].pop(),lambda v:v['audits'][0]['operations'].pop(),lambda v:v['audits'][1]['operations'][0].update(integer=False),lambda v:v['audits'][0]['unknown'].append('unreviewed'),lambda v:v['source']['diagnostics'][0].update(operation='wrong'),lambda v:v['carry'][0].update(frame='wrong'),lambda v:v['carry'][0]['steps'][0].update(correct=False),lambda v:v['carry'][1]['steps'].pop(),lambda v:v['carry'][0].update(buffer='other'),lambda v:v['carry'][0]['unknown'].append('unknown'),lambda v:v['state'][0].update(frame='wrong'),lambda v:v['state'][1]['steps'][0].update(correct=False),lambda v:v['state'][0]['steps'].pop(),lambda v:v['state'][1]['roles'].update(source_cursor='other'),lambda v:v['state'][1]['unknown'].append('unknown'),lambda v:v['state'][1].update(scope=['arbitrary Unicode']),lambda v:v['cursor'][0].update(frame='wrong'),lambda v:v['cursor'][0]['steps'][1].update(correct=False),lambda v:v['cursor'][0]['projection'].pop(),lambda v:v['cursor'][1]['roles'].update(source_cursor='other'),lambda v:v['cursor'][0]['unknown'].append('unproved'),lambda v:v['guard'][0].update(frame='wrong'),lambda v:v['guard'][1]['steps'][0].update(correct=False),lambda v:v['guard'][0]['roles'].update(size='other'),lambda v:v['guard'][0]['steps'].pop(),lambda v:v['guard'][1]['scope'].pop(),lambda v:v['guard'][1]['unknown'].append('unproved'),lambda v:v['prefix'][0].update(frame='wrong'),lambda v:v['prefix'][0]['steps'][0].update(correct=False),lambda v:v['prefix'][1]['steps'].pop(),lambda v:v['prefix'][0]['roles'].update(first_length_use='earlier'),lambda v:v['prefix'][1]['roles'].update(source_offset='other'),lambda v:v['prefix'][1]['projection'].pop(),lambda v:v['prefix'][0]['unknown'].append('unproved')]:
            with self.subTest(change=change):
                self.mutate(change)
    def test_codec_output_is_diagnostic(self):
        self.mutate(lambda v:v['source']['diagnostics'][0].update(encoded='different',decode_error='diagnostic only'),False)
    def test_case_omission_duplicate_statement_or_receipt_mismatch(self):
        for action in ['missing','duplicate','statement','receipt']:
            raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case']==checker.CASE)
            if action=='missing':raw['cases'].remove(c)
            elif action=='duplicate':raw['cases'].append(copy.deepcopy(c))
            elif action=='statement':c['observations'][0]['statement']='other'
            else:c['observations'][1]['observed']='{}'
            with self.assertRaises(AssertionError):checker.verify_integer_source(raw,self.report)
