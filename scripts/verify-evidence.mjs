#!/usr/bin/env node
// Independent verifier: Node's crypto API, no imports from the application.
import {createPublicKey,verify,createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {pathToFileURL} from "node:url";
function canonical(x){if(Array.isArray(x))return "["+x.map(canonical).join(",")+"]";if(x&&typeof x==="object")return "{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+canonical(x[k])).join(",")+"}";return JSON.stringify(x);}
const digest=x=>createHash("sha256").update(typeof x==="string"?x:canonical(x)).digest("base64url");
function resolve(did){if(!did.startsWith("did:key:z"))throw Error("Unsupported DID");let n=0n;const alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";for(const c of did.slice(9)){const j=alphabet.indexOf(c);if(j<0)throw Error("Invalid DID");n=n*58n+BigInt(j);}const bytes=[];while(n){bytes.unshift(Number(n%256n));n/=256n;}if(bytes.length!==34||bytes[0]!==237||bytes[1]!==1)throw Error("Not Ed25519");return createPublicKey({key:{kty:"OKP",crv:"Ed25519",x:Buffer.from(bytes.slice(2)).toString("base64url")},format:"jwk"});}
function jws(t,did,typ="trustcut+jwt"){const parts=t.split(".");if(parts.length!==3)throw Error("Malformed token");const [h,p,s]=parts,header=JSON.parse(Buffer.from(h,"base64url"));if(canonical(header)!==canonical({alg:"EdDSA",kid:did+"#"+did.slice(8),typ}))throw Error("Wrong signature header");if(!verify(null,Buffer.from(h+"."+p),resolve(did),Buffer.from(s,"base64url")))throw Error("Bad signature");return JSON.parse(Buffer.from(p,"base64url"));}
export function independentlyVerify(b,root,auditor){
 if(!root||!auditor||b.rootDid!==root||b.auditorDid!==auditor||b.format!=="trustcut/evidence/v1")throw Error("Pinned trust anchors required");
 const c=jws(b.checkpoint,auditor);if(c.type!=="trustcut/checkpoint/v1"||c.rootDid!==root||c.auditorDid!==auditor||c.eventCount!==b.events.length||c.exportedAt!==b.exportedAt||c.ledgerHash!==digest(b.ledger)||c.credentialHash!==digest(b.credentials))throw Error("Checkpoint mismatch");
 let head="GENESIS";for(const e of b.events){const d=jws(e.token,auditor);if(d.type!=="trustcut/receipt/v1"||d.previousHash!==head||e.previousHash!==head||e.hash!==digest(e.token))throw Error("Broken chain");for(const k of ["id","kind","actor","verdict","reason","timestamp","requestId","decision"])if(canonical(e[k])!==canonical(d[k]))throw Error("Display metadata changed");head=e.hash;}if(c.head!==head)throw Error("Truncated chain");
 const creds=b.credentials.map(t=>{const raw=JSON.parse(Buffer.from(t.split(".")[1],"base64url"));return jws(t,raw.issuer,"vc+jwt");});
 const supplier=creds.find(x=>x.issuer===root&&x.type.includes("AgentIdentityCredential")&&x.credentialSubject.role==="Supplier agent")?.credentialSubject.id;
 for(const o of b.ledger){const d=jws(o.acceptance,supplier);for(const k of ["id","requestId","actor","amountCents","timestamp","authority"])if(canonical(o[k])!==canonical(d[k]))throw Error("Order altered");}
 return {valid:true,receipts:b.events.length,credentials:creds.length,orders:b.ledger.length,claim:"Historical gateway-attested sandbox evidence; no claim of current authority or external delivery."};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{const [, , file,root,auditor]=process.argv;if(!file||!root||!auditor)throw Error("Usage: node scripts/verify-evidence.mjs evidence.json PINNED_ROOT_DID PINNED_AUDITOR_DID");console.log(JSON.stringify(independentlyVerify(JSON.parse(readFileSync(file,"utf8")),root,auditor),null,2));}catch(e){console.error(e.message);process.exitCode=1;}}
