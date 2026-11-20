import sys
from pathlib import Path

ROOT = Path(r"C:\Users\bundy\AppData\Local\Temp\opencode\cloud-security")
sys.path.insert(0, str(ROOT / "report"))
import make_cspm as m

before, bt, bn = m.load("before")
after, at, an = m.load("after")
changed = [c for c in before if before[c]["fail"] and c in after and not after[c]["fail"] and after[c]["pass"]]
print(len(changed))
for c in sorted(changed):
    print(" ", c, before[c]["fail"], "->", after[c]["pass"])
print("disappeared fails:", [c for c in before if before[c]["fail"] and c not in after])
print("fail totals", dict(bt), dict(at))
