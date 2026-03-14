import json
from typing import Any, Dict, List
def load_har(path: str)->Dict[str,Any]:
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        return json.load(f)
def extract_requests(har: Dict[str,Any], limit:int=200)->List[Dict[str,Any]]:
    entries=har.get("log",{}).get("entries",[])
    out=[]
    for e in entries[:limit]:
        req=e.get("request",{})
        res=e.get("response",{})
        out.append({
            "method": req.get("method",""),
            "url": req.get("url",""),
            "headers": {h.get("name",""): h.get("value","") for h in req.get("headers",[]) if h.get("name")},
            "postData": (req.get("postData",{}) or {}).get("text",""),
            "status": res.get("status",0),
            "responseText": ((res.get("content",{}) or {}).get("text","") or "")[:4000],
            "mimeType": ((res.get("content",{}) or {}).get("mimeType","") or ""),
        })
    return out
