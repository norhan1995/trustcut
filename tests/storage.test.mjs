import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import {createState,prepare,execute,revoke} from '../lib/engine.mjs';
const sql=new DatabaseSync(':memory:');
sql.exec(readFileSync(new URL('../drizzle/0000_chief_solo.sql',import.meta.url),'utf8'));
// Run the production repository SQL against real SQLite; this adapter only maps D1's API.
globalThis.__trustcut_test_db = {
  prepare(query) {
    return {
      bind(...params) {
        return {
          async first() { return sql.prepare(query).get(...params) || null; },
          async run() { const r=sql.prepare(query).run(...params); return {meta:{changes:Number(r.changes)}}; }
        };
      }
    };
  }
};
const src=readFileSync(new URL('../lib/repository.ts',import.meta.url),'utf8').replace('import {env} from "cloudflare:workers";','const env={DB:globalThis.__trustcut_test_db};');
const js=ts.transpileModule(src,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {load,insert,commit}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
test('8 competing snapshots commit exactly one order and one budget debit',async()=>{const s=await createState('race');await prepare(s);await insert(s);const clones=await Promise.all(Array.from({length:8},()=>load(s.id)));await Promise.all(clones.map(c=>execute(c,c.pending)));const results=await Promise.all(clones.map(c=>commit(c,0)));assert.equal(results.filter(Boolean).length,1);const saved=await load(s.id);assert.equal(saved.ledger.length,1);assert.equal(saved.spent[saved.rootMandate],18000);assert.equal(saved.nonces.length,1);});
test('revocation committed first makes stale ALLOW fail CAS, retry denies',async()=>{const s=await createState('cut');await prepare(s);await insert(s);const stale=await load(s.id),fresh=await load(s.id);await execute(stale,stale.pending);await revoke(fresh);assert.equal(await commit(fresh,0),true);assert.equal(await commit(stale,0),false);const retry=await load(s.id);assert.equal((await execute(retry,retry.pending)).code,'AUTHORITY_REVOKED');assert.equal(await commit(retry,1),true);assert.equal((await load(s.id)).ledger.length,0);});
test('database-time deadline rejects a now-expired ALLOW',async()=>{const s=await createState('late');await prepare(s);await insert(s);await execute(s,s.pending);assert.equal(await commit(s,0,Date.now()-1),false);assert.equal((await load(s.id)).ledger.length,0);});
test('expired sandbox cannot load or commit',async()=>{const s=await createState('expired');await insert(s);sql.prepare('UPDATE sandboxes SET expires_at=? WHERE id=?').run(Date.now()-1,s.id);assert.equal(await load(s.id),null);assert.equal(await commit(s,0),false);});
