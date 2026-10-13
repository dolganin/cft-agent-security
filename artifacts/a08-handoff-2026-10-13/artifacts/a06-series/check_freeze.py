from pathlib import Path
import hashlib,json,subprocess,sys
from evaluation.scanner_baseline import load_profile,validate_target
root=Path.cwd(); base=root/"artifacts/a06-series"
s=json.loads((base/"freeze-before-series.json").read_text())
assert subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()==s["commit"]
for p,d in s["tracked_sha256"].items():
    assert hashlib.sha256((root/p).read_bytes()).hexdigest()==d, p
profile,lock=load_profile()
files=validate_target(root/"artifacts/benchmark-target/juice-shop",profile)
receipt={"project_commit":s["commit"],"all_tracked_files_unchanged":True,"tracked_files":len(s["tracked_sha256"]),"target_commit":profile.target_commit,"target_files":len(files),"target_files_sha256":files,"profile":profile.model_dump(mode="json"),"scanner_lock":lock}
name=sys.argv[1]
output=base/(name+"-freeze-check.json")
assert not output.exists()
output.write_text(json.dumps(receipt,indent=2)+"\n")
print("Freeze verified:",name,len(files),"target files")
