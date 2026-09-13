
import {env} from "cloudflare:workers";
function db(){if(!env.DB)throw Error("Storage unavailable");return env.DB;}
export async function load(id:string){const r=await db().prepare("SELECT state,revision FROM sandboxes WHERE id=? AND expires_at>?").bind(id,Date.now()).first<{state:string;revision:number}>();if(!r)return null;return {...JSON.parse(r.state),revision:r.revision};}
export async function insert(s:any){await db().prepare("INSERT INTO sandboxes(id,revision,state,expires_at) VALUES(?,?,?,?)").bind(s.id,s.revision,JSON.stringify(s),Date.now()+86400000).run();await db().prepare("DELETE FROM sandboxes WHERE id IN (SELECT id FROM sandboxes WHERE expires_at<? LIMIT 10)").bind(Date.now()).run();}
export async function commit(s:any,revision:number,expires=Number.MAX_SAFE_INTEGER){s.revision=revision+1;const r=await db().prepare("UPDATE sandboxes SET state=?,revision=? WHERE id=? AND revision=? AND expires_at>? AND ?>((julianday('now')-2440587.5)*86400000)").bind(JSON.stringify(s),s.revision,s.id,revision,Date.now(),expires).run();return r.meta.changes===1;}
