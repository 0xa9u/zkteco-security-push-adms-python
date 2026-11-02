#!/usr/bin/env python3
"""Standalone ZKTeco ADMS / Security PUSH diagnostic receiver."""
import argparse,base64,hashlib,json,logging,os,re,secrets,threading
from datetime import datetime,timezone
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit,parse_qs

LOG=logging.getLogger("zkprobe")
LOCK=threading.Lock()
MAX_BODY=1024*1024

def now():
    return datetime.now(timezone.utc).isoformat()

def parse_records(body,table):
    decoded=body.decode("utf-8",errors="replace")
    records=[]
    for line in decoded.splitlines():
        if not line.strip(): continue
        fields=dict(re.findall(r'(?:(?<=\t)|^)\s*([A-Za-z_][A-Za-z_0-9]*)=([^\t\r\n]*)',line))
        if table.lower()=="attlog" and not fields:
            parts=line.split("\t")
            if parts: fields={"pin":parts[0],"time":parts[1] if len(parts)>1 else ""}
        records.append({"parsed":fields,"text_preview":line[:400]})
    return records[:100]

def redact_response(text):
    return re.sub(r'(?m)^(RegistryCode|SessionID)=.*$',r'\1=<redacted>',text)

class ProbeHandler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    server_version="ZK-Push-Probe/2.0"
    def log_message(self,fmt,*args):
        LOG.info("http client=%s %s",self.client_address[0],fmt%args)
    def respond(self,content="OK",status=200,content_type="text/plain; charset=utf-8"):
        raw=content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",content_type)
        self.send_header("Content-Length",str(len(raw)))
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        try:self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError):LOG.warning("device disconnected while responding")
    def do_GET(self):self.handle_request_("GET")
    def do_POST(self):self.handle_request_("POST")
    def handle_request_(self,method):
        uri=urlsplit(self.path)
        qs=parse_qs(uri.query,keep_blank_values=True)
        path=uri.path.rstrip("/") or "/"
        allowed={"/iclock/cdata","/iclock/registry","/iclock/getrequest","/iclock/devicecmd","/iclock/ping","/iclock/fdata","/iclock/exchange","/iclock/push"}
        if path not in allowed:
            self.respond("Not found",404);return
        try:size=int(self.headers.get("Content-Length","0"))
        except ValueError:
            self.respond("Bad Content-Length",400);return
        if self.headers.get("Transfer-Encoding"):
            self.respond("Chunked requests not supported",501);return
        if size<0 or size>MAX_BODY:
            self.respond("Payload too large",413);return
        body=self.rfile.read(size) if size else b""
        sn=(qs.get("SN") or qs.get("sn") or [""])[0]
        table=(qs.get("table") or [""])[0]
        record={
            "time_utc":now(),"peer_ip":self.client_address[0],
            "method":method,"path":path,"query":uri.query,
            "serial":sn,"table":table,
            "content_type":self.headers.get("Content-Type",""),
            "body_len":len(body),"body_sha256":hashlib.sha256(body).hexdigest(),
            "body_base64":base64.b64encode(body).decode("ascii"),
            "body_text":body.decode("utf-8","replace"),
            "records":parse_records(body,table) if body and table.lower() in ("rtlog","attlog","operlog","transaction") else []
        }
        try:
            with LOCK:
                with open(self.server.output,"a",encoding="utf-8") as f:
                    f.write(json.dumps(record,ensure_ascii=False)+"\n");f.flush();os.fsync(f.fileno())
        except OSError as exc:
            LOG.error("failed to journal request: %s",exc)
            self.respond("Journal unavailable",503);return
        if self.server.serial and sn and sn!=self.server.serial:
            LOG.warning("different serial from expected: %r",sn)
        if body:
            LOG.info("%s %s from=%s sn=%s table=%s bytes=%d sha256=%s",method,path,self.client_address[0],sn,table,len(body),record["body_sha256"][:16])
            for item in record["records"][:10]:
                fields=item["parsed"]
                if fields: LOG.info("  EVENT %s",json.dumps(fields,ensure_ascii=False))
                else:LOG.info("  BODY %s",item["text_preview"][:250])
            if not record["records"]:LOG.info("  BODY preview=%r",record["body_text"][:400])
        else:LOG.info("%s %s from=%s query=%s (empty body)",method,path,self.client_address[0],uri.query)
        response,response_type=self.server.make_response(method,path,qs,sn,body)
        try:
            with LOCK:
                with open(self.server.output,"a",encoding="utf-8") as f:
                    f.write(json.dumps({
                        "time_utc":now(),"direction":"response",
                        "peer_ip":self.client_address[0],"serial":sn,
                        "response_type":response_type,"status":200,
                        "response_length":len(response.encode("utf-8")),
                        "response_sha256":hashlib.sha256(response.encode()).hexdigest(),
                        "response_text_redacted":redact_response(response)
                    })+"\n");f.flush();os.fsync(f.fileno())
        except OSError as exc:
            LOG.error("cannot journal response: %s",exc)
            self.respond("Journal unavailable",503);return
        response_ct="application/push; charset=UTF-8" if response_type=="security_push_configuration" else "text/plain; charset=utf-8"
        self.respond(response,content_type=response_ct)
        LOG.info("  response=%s HTTP 200 bytes=%d content=%s",response_type,len(response.encode("utf-8")),redact_response(response)[:360])

class ProtocolState:
    def __init__(self,state_path,expected_serial,mode="security",protocol_version="3.0.1"):
        self.path=Path(state_path)
        self.expected_serial=expected_serial
        self.mode=mode
        self.protocol_version=protocol_version
        self.lock=threading.RLock()
        self.state={}
        if self.path.exists():self.state=json.loads(self.path.read_text(encoding="utf-8"))
    def persist(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        temp=self.path.with_name(self.path.name+".tmp")
        with open(temp,"w",encoding="utf-8") as f:
            json.dump(self.state,f,indent=2);f.flush();os.fsync(f.fileno())
        os.chmod(temp,0o600);os.replace(temp,self.path)
    def make_response(self,method,path,qs,sn,body):
        serial=sn or self.expected_serial
        options=(qs.get("options") or [""])[0].lower()
        category=(qs.get("c") or [""])[0].lower()
        table=(qs.get("table") or [""])[0].lower()
        with self.lock:
            if self.mode=="attendance":
                if method=="GET" and path=="/iclock/cdata" and options=="all":
                    return ("GET OPTION FROM: "+serial+"\n"
                            "Stamp=0\nOpStamp=0\nPhotoStamp=0\n"
                            "ErrorDelay=60\nDelay=30\nTransInterval=1\n"
                            "TransFlag=TransData AttLog OpLog EnrollUser ChgUser\n"
                            "Realtime=1\nEncrypt=0\n"),"attendance_options"
                return "OK","attendance_ack"
            if method=="POST" and (path=="/iclock/registry" or (path=="/iclock/cdata" and category=="registry")):
                state=self.state.get(serial)
                if not state:
                    state={"registry_code":secrets.token_hex(12),"session_id":secrets.randbelow(2147483646)+1,"registered_at":now()}
                    self.state[serial]=state;self.persist()
                return "RegistryCode="+state["registry_code"]+"\n","security_registry"
            if path=="/iclock/cdata" and method=="GET" and options=="all":
                state=self.state.get(serial)
                if not state:return "OK","security_unregistered"
                return ("registry=ok\n"
                        f'RegistryCode={state["registry_code"]}\n'
                        "ServerVersion=2.0\n"
                        "ServerName=ZK-Push-Probe\n"
                        f"PushProtVer={self.protocol_version}\n"
                        "ErrorDelay=60\nRequestDelay=30\n"
                        "TransTimes=00:00;12:00\n"
                        "TransInterval=1\n"
                        "TransTables=User Transaction\n"
                        "Realtime=1\n"
                        f'SessionID={state["session_id"]}\n'
                        "TimeoutSec=30\n"),"security_registered_options"
            if path=="/iclock/push" and method in ("GET","POST"):
                state=self.state.get(serial)
                if not state:return "OK","security_push_not_registered"
                return ("ServerVersion=3.0.1\n"
                        "ServerName=ZK-Push-Probe\n"
                        f"PushVersion={self.protocol_version}\n"
                        "ErrorDelay=60\n"
                        "RequestDelay=10\n"
                        "TransTimes=00:00;12:00\n"
                        "TransInterval=1\n"
                        "TransTables=User Transaction\n"
                        "Realtime=1\n"
                        f'SessionID={state["session_id"]}\n'
                        "TimeoutSec=30\n"),"security_push_configuration"
            if path=="/iclock/getrequest" and method=="GET":return "OK","no_pending_commands"
            if path=="/iclock/exchange":return "OK","unsupported_secure_exchange_diagnostic_only"
            if method=="POST" and path=="/iclock/cdata":return "OK","security_data_ack_"+(table or "unknown")
            return "OK","diagnostic_ack"

class Server(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host",default="127.0.0.1")
    p.add_argument("--port",type=int,default=6000)
    p.add_argument("--allowed-ip",default="",help="Reject requests from any other IP")
    p.add_argument("--serial",default="")
    p.add_argument("--mode",choices=["security","attendance"],default="security")
    p.add_argument("--protocol-version",default="3.0.1")
    p.add_argument("--state",default="./zkteco_registration_state.json")
    p.add_argument("--output",default="./zkteco_requests.jsonl")
    args=p.parse_args()
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    output=Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True,exist_ok=True)
    output.touch(mode=0o600,exist_ok=True)
    os.chmod(output,0o600)
    class RestrictedHandler(ProbeHandler):
        def handle_request_(self,method):
            if args.allowed_ip and self.client_address[0]!=args.allowed_ip:
                self.respond("Forbidden",403);return
            return super().handle_request_(method)
    server=Server((args.host,args.port),RestrictedHandler)
    server.output=output;server.serial=args.serial
    protocol=ProtocolState(args.state,args.serial,args.mode,args.protocol_version)
    server.make_response=protocol.make_response
    server.mode=args.mode
    LOG.info("Listening on http://%s:%s; allow=%s; mode=%s; journal=%s",args.host,args.port,args.allowed_ip,args.mode,output)
    LOG.warning("DIAGNOSTIC ONLY: registration responses are protocol-shaped but secure exchange/authentication is NOT implemented.")
    try:server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:pass
    finally:server.server_close()

if __name__=="__main__":main()
