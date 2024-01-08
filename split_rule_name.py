import traceback

with open("rule_split.txt", "r") as f:
    data = f.readlines()
output = set()
for des in data:
    if str(des).strip() != "" and "REASON" in des:
        import re

        pattern = r".*REASON_.*: Yara Rule MATCH: ([^\s]+) SUBSCORE: (\d+) DESCRIPTION: (.+?) REF: (.*)$"
        try:
            match = re.search(pattern, str(des).strip())
            output.add(match.group(1).strip())
        except:
            try:
                pattern = r".*REASON_.*: (\S+).*TYPE: (.*)"
                match = re.search(pattern, str(des).strip())
                output.add(match.group(1).strip())
            except:
                traceback.print_exc()
res = []
for i in output:
    if "webshell" in str(i).lower() or "jsp" in str(i).lower() or "asp" in str(
            i).lower() or "php" in str(i).lower() or "web" in str(
        i).lower() or "shell" in str(i).lower() or "cmd" in str(i).lower():

        pass
    else:
        res.append(i)
with open("rule_split.txt", "w") as f:
    f.write("\n".join(res))
