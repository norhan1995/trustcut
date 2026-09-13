
import {identity,sign,verify,decode,hash,tamper} from "./crypto.mjs";
export const POLICY="trustcut/policy/1.0";
const uuid=()=>crypto.randomUUID();
const ctx=["https://www.w3.org/ns/credentials/v2",{
AgentIdentityCredential:"urn:trustcut:AgentIdentityCredential",ScopedDelegationCredential:"urn:trustcut:ScopedDelegationCredential",SupplierAttestationCredential:"urn:trustcut:SupplierAttestationCredential",
scope:{"@id":"urn:trustcut:scope","@type":"@json"},role:"urn:trustcut:role",parentHash:"urn:trustcut:parentHash",rootId:{"@id":"urn:trustcut:rootId","@type":"@id"},domain:"urn:trustcut:domain",statement:"urn:trustcut:statement"}];
export function credential(issuer,subject,type,now=Date.now()){return {"@context":ctx,id:"urn:uuid:"+uuid(),type:["VerifiableCredential",type],issuer,validFrom:new Date(now-1000).toISOString(),validUntil:new Date(now+3600000).toISOString(),credentialSubject:subject};}
export async function grant(key,subject,scope,now,parent){const c=credential(key.did,{id:subject,scope},"ScopedDelegationCredential",now);c.credentialSubject.rootId=parent?decode(parent).credentialSubject.rootId:c.id;if(parent){const p=decode(parent);c.credentialSubject.parentHash=await hash(parent);c.validFrom=p.validFrom;c.validUntil=p.validUntil;}return sign(c,key,"vc+jwt");}
export async function createState(id,now=Date.now()){
 const names={principal:["Northstar","Human principal"],atlas:["Atlas","Coordinator"],relay:["Relay","Buyer agent"],scout:["Scout","Sibling buyer"],harbor:["Harbor","Supplier agent"],auditor:["Witness","Evidence verifier"],intruder:["Mirror","Adversarial agent"]},actors={};
 for(const [alias,[name,role]]of Object.entries(names))actors[alias]={...await identity(),alias,name,role};
 for(const a of Object.values(actors))a.credential=await sign(credential(actors.principal.did,{id:a.did,name:a.name,role:a.role},"AgentIdentityCredential",now),actors.principal,"vc+jwt");
 const scope={actions:["order:create"],resources:["clinic:stock"],counterparties:[actors.harbor.did],maxCents:60000,budgetCents:60000,depth:2};
 const root=await grant(actors.principal,actors.atlas.did,scope,now);
 const chains={};for(const alias of ["relay","scout"])chains[alias]=[root,await grant(actors.atlas,actors[alias].did,{...scope,maxCents:30000,depth:1},now,root)];
 const vouch=await sign(credential(actors.auditor.did,{id:actors.harbor.did,domain:"clinic:stock",statement:"Seeded sandbox supplier eligibility; not an external business certification."},"SupplierAttestationCredential",now),actors.auditor,"vc+jwt");
 return {id,revision:0,createdAt:now,actors,chains,vouch,rootMandate:decode(root).id,revoked:[],revocations:[],spent:{},nonces:[],approvals:{},pending:null,lastPacket:null,lastDecision:null,events:[],ledger:[],epoch:0,suspended:false};
}
export async function packet(s,amountCents=18000,alias="relay",now=Date.now(),changes={}){
 const chain=[...s.chains[alias]];
 const intent={type:"trustcut/intent/v1",id:uuid(),actor:s.actors[alias].did,audience:s.actors.harbor.did,action:"order:create",resource:"clinic:stock",purpose:"Restock Northstar clinic supplies",amountCents,currency:"USD",nonce:uuid(),issuedAt:now,expiresAt:now+120000,chainHash:await hash(chain),...changes};
 return {intent:await sign(intent,s.actors[alias]),chain,identity:s.actors[alias].credential,counterparty:s.actors.harbor.credential,vouch:s.vouch};
}
const alive=(c,n)=>Number.isFinite(Date.parse(c.validFrom))&&Number.isFinite(Date.parse(c.validUntil))&&Date.parse(c.validFrom)<=n&&n<Date.parse(c.validUntil);
function shape(c,t){return c&&Array.isArray(c["@context"])&&c["@context"][0]===ctx[0]&&Array.isArray(c.type)&&c.type.includes("VerifiableCredential")&&c.type.includes(t)&&typeof c.id==="string"&&c.id.startsWith("urn:uuid:")&&typeof c.credentialSubject?.id==="string";}
function scopeOK(s){return s&&["actions","resources","counterparties"].every(k=>Array.isArray(s[k])&&s[k].length>0&&s[k].length<=10&&s[k].every(x=>typeof x==="string"))&&Number.isSafeInteger(s.maxCents)&&s.maxCents>0&&Number.isSafeInteger(s.budgetCents)&&s.budgetCents>=s.maxCents&&s.budgetCents<=100000000&&Number.isSafeInteger(s.depth)&&s.depth>=0&&s.depth<=4;}
export async function evaluate(p,s,now=Date.now()){
 const checks=[],pass=(code,label,detail)=>checks.push({code,label,detail,status:"pass"});
 const stop=(code,label,reason,repair=null,verdict="DENY")=>{checks.push({code,label,detail:reason,status:verdict==="ESCALATE"?"hold":"fail"});return {verdict,code,reason,repair,checks};};
 try{
 if(!p||!Array.isArray(p.chain)||p.chain.length<1||p.chain.length>4)return stop("MALFORMED","Packet schema","Malformed or excessive delegation chain.");
 let i=decode(p.intent);
 if(i.type!=="trustcut/intent/v1"||!Number.isSafeInteger(i.amountCents)||i.amountCents<1||i.amountCents>100000000||i.currency!=="USD"||typeof i.actor!=="string"||!(/^[0-9a-f-]{36}$/).test(i.id)||!(/^[0-9a-f-]{36}$/).test(i.nonce)||typeof i.purpose!=="string"||i.purpose.length>300)return stop("MALFORMED","Request schema","Invalid signed request fields.");
 try{i=await verify(p.intent,i.actor);}catch{return stop("BAD_SIGNATURE","Holder signature","These exact request bytes were not signed by the claimed agent.");}
 pass("HOLDER_PROOF","Holder signature","Ed25519 proves control of the acting key.");
 let ident;try{ident=await verify(p.identity,s.actors.principal.did,"vc+jwt");}catch{return stop("UNTRUSTED_IDENTITY","Trusted issuer","The identity credential is not signed by Northstar's pinned key.");}
 if(!shape(ident,"AgentIdentityCredential")||ident.issuer!==s.actors.principal.did||ident.credentialSubject.id!==i.actor||!alive(ident,now)||s.revoked.includes(ident.id))return stop("IDENTITY_INVALID","Agent identity","Identity is expired, revoked, or belongs to another holder.");
 pass("IDENTITY_VERIFIED","Agent identity","Northstar binds this key to the acting agent.");
 if(i.audience!==s.actors.harbor.did)return stop("WRONG_AUDIENCE","Recipient binding","The request is intended for a different recipient.");
 let counter;try{counter=await verify(p.counterparty,s.actors.principal.did,"vc+jwt");}catch{return stop("COUNTERPARTY_SPOOF","Counterparty proof","The supplier identity signature failed.");}
 if(!shape(counter,"AgentIdentityCredential")||counter.credentialSubject.id!==i.audience||counter.issuer!==s.actors.principal.did||!alive(counter,now)||s.revoked.includes(counter.id)||p.counterparty!==s.actors.harbor.credential)return stop("COUNTERPARTY_INVALID","Counterparty proof","The supplier is not currently recognized for this exchange.");
 pass("COUNTERPARTY_VERIFIED","Mutual verification","The buyer and supplier verify each other's credential and recipient binding.");
 if(!Number.isSafeInteger(i.issuedAt)||!Number.isSafeInteger(i.expiresAt)||i.issuedAt>now||i.expiresAt<=now||i.expiresAt<=i.issuedAt||i.expiresAt-i.issuedAt>120000)return stop("REQUEST_EXPIRED","Freshness","The request is expired, future-dated, or outside its two-minute window.");
 if(s.nonces.includes(i.nonce))return stop("REPLAY","One-time request","This exact nonce already committed an order.");
 pass("FRESH_NONCE","Freshness and replay","Fresh request; its nonce has not executed.");
 if(i.chainHash!==await hash(p.chain))return stop("CHAIN_SUBSTITUTION","Chain binding","Presented authority differs from the chain the actor signed.");
 const chain=[];let expected=s.actors.principal.did;
 for(let n=0;n<p.chain.length;n++){
 let c;try{c=await verify(p.chain[n],expected,"vc+jwt");}catch{return stop("DELEGATION_SIGNATURE","Grant signature","A delegation signature or issuer is invalid.");}
 if(!shape(c,"ScopedDelegationCredential")||c.issuer!==expected||!scopeOK(c.credentialSubject.scope))return stop("DELEGATION_INVALID","Grant schema","The authority is not a bounded delegation.");
 if(!alive(c,now))return stop("DELEGATION_EXPIRED","Grant lifetime","A mandate is expired or not yet valid.");
 if(s.revoked.includes(c.id))return stop("AUTHORITY_REVOKED","Live revocation","Northstar cut the parent mandate. All authority derived from it is invalid.","Obtain a new mandate. Human approval cannot restore a revoked grant.");
 const prev=chain[n-1],sc=c.credentialSubject.scope;
 if(prev){const ps=prev.credentialSubject.scope;
 if(c.credentialSubject.parentHash!==await hash(p.chain[n-1])||c.credentialSubject.rootId!==chain[0].id)return stop("BROKEN_CHAIN","Parent linkage","The grant does not reference its exact parent.");
 if(!["actions","resources","counterparties"].every(k=>sc[k].every(v=>ps[k].includes(v)))||sc.maxCents>ps.maxCents||sc.budgetCents>ps.budgetCents||sc.depth>=ps.depth||Date.parse(c.validFrom)<Date.parse(prev.validFrom)||Date.parse(c.validUntil)>Date.parse(prev.validUntil))return stop("PRIVILEGE_ESCALATION","Scope attenuation","A child grant expands its parent's power, depth, or lifetime.");
 }else if(c.credentialSubject.rootId!==c.id||c.credentialSubject.parentHash)return stop("INVALID_ROOT","Authority root","Malformed root mandate.");
 if(chain.some(x=>x.id===c.id||x.credentialSubject.id===c.credentialSubject.id))return stop("DELEGATION_CYCLE","Chain topology","A repeated authority or cycle was detected.");
 chain.push(c);expected=c.credentialSubject.id;
 }
 if(expected!==i.actor)return stop("HOLDER_MISMATCH","Authority holder","This chain delegates to a different agent.");
 pass("CHAIN_VERIFIED","Narrowing delegation","Every hop is signed, linked, and no broader than its parent.");
 pass("REVOCATION_CURRENT","Live revocation","Every ancestor is active in this authority snapshot.");
 for(const c of chain){const sc=c.credentialSubject.scope;
 if(!sc.actions.includes(i.action)||!sc.resources.includes(i.resource)||!sc.counterparties.includes(i.audience)||i.amountCents>sc.maxCents)return stop("SCOPE_EXCEEDED","Action scope","The action, resource, recipient, or amount exceeds the mandate.","Use a narrower request or ask the principal for a fresh scoped grant.");
 if((s.spent[c.id]||0)+i.amountCents>sc.budgetCents)return stop("BUDGET_EXHAUSTED","Shared budget","Sibling agents share one parent budget. This order would overspend it.","New budget requires a fresh principal grant; splitting across agents adds no authority.");
 }
 pass("SCOPE_VALID","Action scope","Action and amount fit every ancestor's explicit scope.");
 pass("BUDGET_AVAILABLE","Conserved budget","Funds remain under every grant, including the shared parent.");
 if(s.suspended)return stop("STATUS_UNAVAILABLE","Authority availability","Current authority status is unavailable. Execution is held.","Restore the status source and re-evaluate.", "ESCALATE");
 if(!p.vouch)return stop("VOUCH_REQUIRED","Supplier attestation","Harbor lacks a qualifying supplier attestation.","Obtain a current vouch from the trusted auditor.","ESCALATE");
 let v;try{v=await verify(p.vouch,s.actors.auditor.did,"vc+jwt");}catch{return stop("VOUCH_UNTRUSTED","Trusted attestation","An untrusted issuer cannot establish supplier trust.");}
 if(!shape(v,"SupplierAttestationCredential")||v.issuer!==s.actors.auditor.did||v.credentialSubject.id!==i.audience||v.credentialSubject.domain!==i.resource||!alive(v,now)||s.revoked.includes(v.id))return stop("VOUCH_INVALID","Supplier attestation","The vouch does not cover this supplier, scope, or current time.");
 pass("VOUCH_VERIFIED","Scoped attestation","Witness vouches for Harbor in the stock-supply domain only.");
 if(i.amountCents>20000){const h=await hash(p.intent),a=s.approvals[h];
 if(!a)return stop("APPROVAL_REQUIRED","Human checkpoint","This valid request exceeds the $200 automatic threshold.","Northstar must approve the exact signed request before it expires.","ESCALATE");
 try{const d=await verify(a,s.actors.principal.did);if(d.type!=="trustcut/approval/v1"||d.intentHash!==h||d.expiresAt<=now)throw Error();}catch{return stop("APPROVAL_INVALID","Human checkpoint","Approval is invalid, expired, or for another request.");}
 pass("APPROVAL_VERIFIED","Human checkpoint","Northstar approved these exact request bytes.");
 }else pass("WITHIN_AUTO_LIMIT","Human checkpoint","Within the $200 automatic threshold.");
 return {verdict:"ALLOW",code:"AUTHORIZED",reason:"Harbor accepts this authority. Execution will check it again.",repair:null,checks};
 }catch{return stop("MALFORMED","Fail-closed parsing","The evidence could not be safely parsed or verified.");}
}
export async function event(s,kind,d,p=null,now=Date.now()){
 const i=p?decode(p.intent):null;
 const body={type:"trustcut/receipt/v1",id:uuid(),kind,actor:i?.actor||s.actors.principal.did,verdict:d.verdict,reason:d.reason,timestamp:now,requestId:i?.id||null,previousHash:s.events.at(-1)?.hash||"GENESIS",policy:POLICY,epoch:s.epoch,intentHash:p?await hash(p.intent):null,decision:d,ledgerHash:await hash(s.ledger)};
 const token=await sign(body,s.actors.auditor);s.events.push({...body,token,hash:await hash(token)});s.lastDecision=d;
}
export async function prepare(s,amount=18000,now=Date.now()){const p=await packet(s,amount,"relay",now),d=await evaluate(p,s,now);s.pending=p;s.lastPacket=p;await event(s,"PREPARED",d,p,now);return d;}
export async function execute(s,p,now=Date.now()){
 const d=await evaluate(p,s,now);
 if(d.verdict==="ALLOW"){const i=decode(p.intent),ids=p.chain.map(t=>decode(t).id);s.nonces.push(i.nonce);for(const id of ids)s.spent[id]=(s.spent[id]||0)+i.amountCents;
 const order={id:uuid(),requestId:i.id,actor:i.actor,amountCents:i.amountCents,timestamp:now,authority:ids};
 order.acceptance=await sign({type:"trustcut/order-accepted/v1",...order,intentHash:await hash(p.intent)},s.actors.harbor);
 s.ledger.push(order);d.reason="Harbor signed acceptance. The order, nonce, and all ancestor budgets commit together.";}
 s.lastPacket=p;await event(s,d.verdict==="ALLOW"?"EXECUTED":"BLOCKED",d,p,now);if(s.pending?.intent===p.intent)s.pending=null;return d;
}
export async function applyRevocation(s,token,now=Date.now()){
 const r=await verify(token,s.actors.principal.did);
 if(r.type!=="trustcut/revocation/v1"||r.credentialId!==s.rootMandate||r.epoch!==s.epoch+1||!Number.isSafeInteger(r.issuedAt)||r.issuedAt>now||now-r.issuedAt>120000)throw Error("Invalid revocation");
 if(!s.revoked.includes(r.credentialId))s.revoked.push(r.credentialId);s.revocations.push(token);s.epoch=r.epoch;
}
export async function revoke(s,now=Date.now()){if(!s.revoked.includes(s.rootMandate))await applyRevocation(s,await sign({type:"trustcut/revocation/v1",credentialId:s.rootMandate,epoch:s.epoch+1,issuedAt:now},s.actors.principal),now);
 const d={verdict:"DENY",code:"AUTHORITY_REVOKED",reason:"Northstar cut Atlas's mandate. Relay and Scout lose its delegated authority.",repair:"Issue fresh authority to continue.",checks:[]};await event(s,"REVOKED",d,null,now);return d;}
export async function approve(s,now=Date.now()){if(!s.pending)throw Error("Prepare an order first.");const i=decode(s.pending.intent),h=await hash(s.pending.intent);s.approvals[h]=await sign({type:"trustcut/approval/v1",intentHash:h,expiresAt:i.expiresAt},s.actors.principal);const d=await evaluate(s.pending,s,now);await event(s,"APPROVED",d,s.pending,now);return d;}
export function deadline(p){return Math.min(decode(p.intent).expiresAt,...[p.identity,p.counterparty,p.vouch,...p.chain].filter(Boolean).map(t=>Date.parse(decode(t).validUntil)));}
export function publicState(s){return {id:s.id,revision:s.revision,epoch:s.epoch,actors:Object.values(s.actors).filter(a=>a.alias!=="intruder").map(({alias,name,role,did,credential})=>({alias,name,role,did,credential})),chains:s.chains,vouch:s.vouch,rootMandate:s.rootMandate,revoked:s.revoked,suspended:s.suspended,spentCents:s.spent[s.rootMandate]||0,budgetCents:60000,pending:s.pending?{requestId:decode(s.pending.intent).id,amountCents:decode(s.pending.intent).amountCents}:null,lastDecision:s.lastDecision,events:s.events,ledger:s.ledger};}
export async function evidence(s,now=Date.now()){const credentials=[...Object.values(s.actors).filter(a=>a.alias!=="intruder").map(a=>a.credential),...s.chains.relay,s.chains.scout[1],s.vouch];const checkpoint=await sign({type:"trustcut/checkpoint/v1",eventCount:s.events.length,head:s.events.at(-1)?.hash||"GENESIS",ledgerHash:await hash(s.ledger),credentialHash:await hash(credentials),rootDid:s.actors.principal.did,auditorDid:s.actors.auditor.did,exportedAt:now},s.actors.auditor);return {format:"trustcut/evidence/v1",rootDid:s.actors.principal.did,auditorDid:s.actors.auditor.did,exportedAt:now,events:s.events,ledger:s.ledger,credentials,checkpoint,claimBoundary:"Historical signed sandbox evidence; not proof of current authority, external delivery, or independent operator custody."};}
export const ATTACKS=[
["spoof","Identity spoof","BAD_SIGNATURE","Mirror signs a request claiming Relay's identity."],
["tamper","Tampered amount","BAD_SIGNATURE","Change $180 to $18 after signing."],
["replay","Replay request","REPLAY","Submit the same signed order twice."],
["escalation","Privilege escalation","PRIVILEGE_ESCALATION","A child grant adds an unauthorized admin action."],
["revocation-race","Revoke after approval","AUTHORITY_REVOKED","Revoke the parent after the first ALLOW."],
["budget","Sibling overspend","BUDGET_EXHAUSTED","Two buyers consume the same parent budget."],
["audience","Wrong recipient","WRONG_AUDIENCE","Use a valid request with another supplier."],
["expired","Expired request","REQUEST_EXPIRED","Present a valid signature after expiry."],
["vouch","Forged vouch","VOUCH_UNTRUSTED","Mirror signs as the trusted auditor."],
["chain","Chain substitution","CHAIN_SUBSTITUTION","Replace the chain after the request is signed."],
["outage","Status outage","STATUS_UNAVAILABLE","Lose the live authority status source."],
["scope","Out-of-scope order","SCOPE_EXCEEDED","Spend $450 with a $300 mandate."]
].map(([id,name,expected,detail])=>({id,name,expected,detail}));
export async function attack(id,now=Date.now()){
 const def=ATTACKS.find(a=>a.id===id);if(!def)throw Error("Unknown attack");const s=await createState(uuid(),now);let p=await packet(s,18000,"relay",now);
 if(id==="spoof")p.intent=await sign(decode(p.intent),s.actors.intruder);
 if(id==="tamper")p.intent=tamper(p.intent,x=>x.amountCents=1800);
 if(id==="replay")await execute(s,p,now);
 if(id==="escalation"){const c=decode(p.chain[1]);c.credentialSubject.scope.actions.push("admin:delete");p.chain[1]=await sign(c,s.actors.atlas,"vc+jwt");p.intent=await sign({...decode(p.intent),chainHash:await hash(p.chain)},s.actors.relay);}
 if(id==="revocation-race"){if((await evaluate(p,s,now)).verdict!=="ALLOW")throw Error("Invalid initial condition");await revoke(s,now);}
 if(id==="budget"){for(let n=0;n<3;n++)await execute(s,await packet(s,18000,n%2?"scout":"relay",now),now);p=await packet(s,18000,"scout",now);}
 if(id==="audience")p=await packet(s,18000,"relay",now,{audience:s.actors.intruder.did});
 if(id==="expired")p=await packet(s,18000,"relay",now-180000);
 if(id==="vouch")p.vouch=await sign(decode(s.vouch),s.actors.intruder,"vc+jwt");
 if(id==="chain")p.chain=[...s.chains.scout];
 if(id==="outage")s.suspended=true;
 if(id==="scope")p=await packet(s,45000,"relay",now);
 const before=s.ledger.length,d=await execute(s,p,now);
 return {id,decision:d,expected:def.expected,passed:d.code===def.expected&&s.ledger.length===before,ordersBefore:before,ordersAfter:s.ledger.length};
}
