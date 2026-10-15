"""Verify the actual Core1.0 minimal representation returned by the same Resolve call."""
from sage_internal_boundary_scope import MEDIA_ID,verify_internal_pending
import argparse,hashlib,io,json,base64,zipfile
from pathlib import Path
from check_sage_internal_operations import verify_internal_operations
from check_sage_fragment_source import REPO
from sage_returned_representation_scope import verify_representation_pending,REPRESENTATION_ID,REPRESENTATION_CASE,MODULE,VERSION,SUM,PACKAGES,data
def verify_returned_representation(raw,report,repo=REPO):
 verify_internal_operations(raw,report,repo);live={x['id']:x for x in report['statements']}
 verify_representation_pending(raw,live)
 cases=[c for c in raw['cases'] if '/returned-minimal-' in c['case']];assert len(cases)==1 and cases[0]['case']==REPRESENTATION_CASE
 e=json.loads(cases[0]['observations'][0]['observed']);s=e['source'];prefix=MODULE+'@'+VERSION+'/'
 with zipfile.ZipFile(io.BytesIO(data(s['archive']))) as z:
  names=z.namelist();assert len(names)==len(set(names)) and names
  assert all(n.startswith(prefix) and '\n' not in n and '\r' not in n for n in names)
  files={n:z.read(n) for n in names}
 lines=''.join(hashlib.sha256(files[n]).hexdigest()+'  '+n+'\n' for n in sorted(files))
 assert 'h1:'+base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()==SUM
 selected={n[len(prefix):]:b for n,b in files.items() if n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
 assert len(selected)==9 and set(selected)==set(s['files']) and all(data(s['files'][n])==b for n,b in selected.items())
 verify_internal_pending(raw,live,MEDIA_ID)
 return {REPRESENTATION_ID}
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();verify_returned_representation(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified two same-call returned Core1.0 minimal representations, distinct input/output versions, nine cache files and complete id-only class')
if __name__=='__main__':main()
