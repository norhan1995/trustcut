
import {createState,publicState,prepare,execute,revoke,approve,attack,evidence,evaluate,deadline,event} from "@/lib/engine.mjs";
import {hash,decode} from "@/lib/crypto.mjs";
import {load,insert,commit} from "@/lib/repository";
export const dynamic="force-dynamic";
const H={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"};
async function session(r:Request){const t=r.headers.get("cookie")?.split(";").map(x=>x.trim()).find(x=>x.startsWith("trustcut_session="))?.slice(17)||"";return /^[0-9a-f-]{73}$/.test(t)?load(await hash(t)):null;}
export async function GET(r:Request){try{const s=await session(r);if(!s)return Response.json({error:"Open a sandbox first."},{status:401,headers:H});const type=new URL(r.url).searchParams.get("export");if(type==="evidence")return Response.json(await evidence(s),{headers:{...H,"Content-Disposition":"attachment; filename=trustcut-evidence.json"}});if(type==="packet")return Response.json(s.lastPacket,{headers:H});return Response.json({state:publicState(s)},{headers:H});}catch{return Response.json({error:"Sandbox storage unavailable."},{status:503,headers:H});}}
export async function POST(r:Request){try{
 const origin=r.headers.get("origin");if(origin&&new URL(origin).host!==new URL(r.url).host)return Response.json({error:"Origin mismatch"},{status:403,headers:H});
 if(!r.headers.get("content-type")?.startsWith("application/json"))return Response.json({error:"JSON required"},{status:415,headers:H});
 const text=await r.text();if(text.length>70000)return Response.json({error:"Request too large"},{status:413,headers:H});
 let input;try{input=JSON.parse(text);}catch{return Response.json({error:"Invalid JSON"},{status:400,headers:H});}
 if(!input||typeof input!=="object"||Array.isArray(input))return Response.json({error:"JSON object required"},{status:400,headers:H});
 const {op}=input;if(!["connect","reset","prepare","execute","approve","revoke","attack","pause-status","resume-status","verify-packet"].includes(op))return Response.json({error:"Unknown action"},{status:400,headers:H});
 let s=await session(r);
 if(op==="connect"&&!s){const token=crypto.randomUUID()+"-"+crypto.randomUUID();s=await createState(await hash(token));await insert(s);return Response.json({state:publicState(s)},{headers:{...H,"Set-Cookie":"trustcut_session="+token+"; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"+(new URL(r.url).protocol==="https:"?"; Secure":"")}});}
 if(!s)return Response.json({error:"Sandbox expired. Reconnect to continue."},{status:401,headers:H});
 if(op==="connect")return Response.json({state:publicState(s)},{headers:H});
 if(op==="attack")return Response.json({attack:await attack(input.attack),state:publicState(s)},{headers:H});
 if(op==="verify-packet")return Response.json({decision:await evaluate(input.packet,s)},{headers:H});
 if(input.amountCents!==undefined&&(!Number.isSafeInteger(input.amountCents)||input.amountCents<1||input.amountCents>100000000))return Response.json({error:"Amount must be positive whole cents."},{status:400,headers:H});
 if(["execute","approve"].includes(op)&&(!s.pending||decode(s.pending.intent).id!==input.requestId))return Response.json({error:"The pending request changed. Refresh before acting."},{status:409,headers:H});
 const frozen=s.pending;const requestId=input.requestId;
 for(let n=0;n<5;n++){
 const rev=s.revision;
 if(s.events.length>=150&&op!=="reset")return Response.json({error:"Sandbox event limit reached. Reset to continue."},{status:409,headers:H});
 if(op==="reset"){s=await createState(s.id);s.revision=rev;}
 if(op==="prepare")await prepare(s,input.amountCents??18000);
 if(op==="execute")await execute(s,frozen);
 if(op==="approve"){if(!s.pending||decode(s.pending.intent).id!==requestId)return Response.json({error:"The request changed. Prepare it again."},{status:409,headers:H});await approve(s);}
 if(op==="revoke")await revoke(s);
 if(op==="pause-status"||op==="resume-status"){s.suspended=op==="pause-status";s.epoch++;await event(s,"STATUS_CHANGED",{verdict:s.suspended?"ESCALATE":"ALLOW",code:s.suspended?"STATUS_UNAVAILABLE":"STATUS_RESTORED",reason:s.suspended?"Authority status is unavailable. Execution will wait.":"Authority status is restored.",checks:[],repair:null});}
 const limit=op==="execute"&&s.lastDecision.verdict==="ALLOW"?deadline(frozen):Number.MAX_SAFE_INTEGER;
 if(await commit(s,rev,limit))return Response.json({state:publicState(s)},{headers:H});
 const current=await load(s.id);if(!current)throw Error("Sandbox expired");s=current;
 }
 return Response.json({error:"Authority changed concurrently. Retry against current state."},{status:409,headers:H});
 }catch(e){console.error("TrustCut action failed",e instanceof Error?e.message.slice(0,120):"unknown");return Response.json({error:"The action could not commit. Reconnect and retry; success is not assumed."},{status:503,headers:H});}}
