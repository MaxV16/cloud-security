import csv, glob, collections

base = r"C:\Users\bundy\AppData\Local\Temp\opencode\cloud-security\evidence\prowler"


def load(which):
    rows = {}
    for f in glob.glob(base + "\\" + which + "\\*.csv"):
        with open(f, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh, delimiter=";"):
                rows[(r["CHECK_ID"], r["RESOURCE_UID"])] = r["STATUS"]
    return rows


b = load("before")
a = load("after")
print("before results", len(b), "fail", sum(1 for v in b.values() if v == "FAIL"))
print("after  results", len(a), "fail", sum(1 for v in a.values() if v == "FAIL"))

only_after = [k for k in a if k not in b]
only_before = [k for k in b if k not in a]
print("only in after", len(only_after), collections.Counter(a[k] for k in only_after))
print("only in before", len(only_before), collections.Counter(b[k] for k in only_before))

trans = collections.Counter()
changed = []
for k in a:
    if k in b and a[k] != b[k]:
        trans[(b[k], a[k])] += 1
        changed.append((k, b[k], a[k]))
print("transitions", dict(trans))
for k, o, n in sorted(changed, key=lambda x: x[0][0]):
    print("  ", k[0], o, "->", n)
