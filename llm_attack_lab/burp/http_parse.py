import re
from typing import Dict, Tuple
def parse_raw_http(raw: str)->Tuple[Dict[str,str], str, str, Dict[str,str], str]:
    raw=raw.replace("\r\n","\n")
    lines=raw.split("\n")
    if not lines:
        return {}, "", "", {}, ""
    first=lines[0].strip()
    m=re.match(r"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)\s+HTTP", first, re.I)
    method=""; path=""
    if m:
        method=m.group(1).upper(); path=m.group(2)
    headers={}
    i=1
    while i<len(lines):
        line=lines[i]; i+=1
        if line.strip()=="":
            break
        if ":" in line:
            k,v=line.split(":",1)
            headers[k.strip()]=v.strip()
    body="\n".join(lines[i:]).strip()
    host=headers.get("Host","")
    url=f"https://{host}{path}" if host else path
    return {"method":method}, url, path, headers, body
