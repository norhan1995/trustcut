import test from 'node:test';
import assert from 'node:assert/strict';
import {createState,prepare,execute,evidence} from '../lib/engine.mjs';
import {verifyEvidence} from '../lib/evidence.mjs';
import {independentlyVerify} from '../scripts/verify-evidence.mjs';
test('browser fallback verifies native signatures and rejects tampering without WebCrypto',async()=>{const s=await createState('fallback');await prepare(s);await execute(s,s.pending);const b=await evidence(s),root=s.actors.principal.did,auditor=s.actors.auditor.did;assert.equal(independentlyVerify(b,root,auditor).valid,true);const original=Object.getOwnPropertyDescriptor(globalThis,'crypto');Object.defineProperty(globalThis,'crypto',{value:{},configurable:true});try{assert.equal((await verifyEvidence(b,root,auditor)).valid,true);b.events[0].reason='forged';assert.equal((await verifyEvidence(b,root,auditor)).valid,false);}finally{Object.defineProperty(globalThis,'crypto',original);}});
