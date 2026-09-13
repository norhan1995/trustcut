
import {verify,hash,canonical,decode} from "./crypto.mjs";
export async function verifyEvidence(b,root,auditor){
 try{
 if(b.format!=="trustcut/evidence/v1"||b.rootDid!==root||b.auditorDid!==auditor||!Array.isArray(b.events)||b.events.length>200)throw Error("Trust anchor or format mismatch");
 const c=await verify(b.checkpoint,auditor);
 if(c.type!=="trustcut/checkpoint/v1"||c.rootDid!==root||c.auditorDid!==auditor||c.eventCount!==b.events.length||c.exportedAt!==b.exportedAt||c.ledgerHash!==await hash(b.ledger)||c.credentialHash!==await hash(b.credentials))throw Error("Checkpoint mismatch");
 let prev="GENESIS";
 for(const e of b.events){const d=await verify(e.token,auditor);if(d.type!=="trustcut/receipt/v1"||d.previousHash!==prev||e.previousHash!==prev||e.hash!==await hash(e.token))throw Error("Broken audit chain");for(const k of ["id","kind","actor","verdict","reason","timestamp","requestId","decision"])if(canonical(d[k])!==canonical(e[k]))throw Error("Modified display metadata");prev=e.hash;}
 if(c.head!==prev)throw Error("Truncated audit trail");
 for(const t of b.credentials){const d=decode(t);await verify(t,d.issuer,"vc+jwt");}
 const harbor=b.credentials.map(decode).find(c=>c.issuer===root&&c.type.includes("AgentIdentityCredential")&&c.credentialSubject.role==="Supplier agent")?.credentialSubject.id;
 for(const o of b.ledger){const d=await verify(o.acceptance,harbor);for(const k of ["id","requestId","actor","amountCents","timestamp","authority"])if(canonical(o[k])!==canonical(d[k]))throw Error("Modified order");}
 return {valid:true,receipts:b.events.length,credentials:b.credentials.length,orders:b.ledger.length,reason:"Signatures, supplier acceptances, audit chain, and pinned checkpoint verified."};
 }catch(e){return {valid:false,receipts:0,credentials:0,orders:0,reason:e.message||"Invalid evidence"};}
}
