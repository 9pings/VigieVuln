"use strict";
const fs=require("node:fs");
const readline=require("node:readline");
const {Writable}=require("node:stream");
const {createAccountClient}=require("./account-client");
const {createAccountSessionStore}=require("./account-session");
const {projectRequest,createProject,updateProject}=require("./project-client");

function prompt(label,secret=false) {
  if (!process.stdin.isTTY || !process.stderr.isTTY) throw new Error("interactive login requires a terminal");
  process.stderr.write(label);
  const output=secret ? new Writable({write(_data,_encoding,done){done();}}) : process.stderr;
  return new Promise(resolve=>{const rl=readline.createInterface({input:process.stdin,output,terminal:true});
    rl.question("",answer=>{rl.close();if(secret)process.stderr.write("\n");resolve(answer);});});
}
function parse(args) {
  const out={};
  for(let i=0;i<args.length;i++) {
    const arg=args[i];if(!['--file','--name','--id'].includes(arg) || !args[i+1] || args[i+1].startsWith('--') || out[arg]) throw new Error(`invalid option ${arg}`);
    out[arg]=args[++i];
  }
  return out;
}
async function ensureSignedIn({account,store,ask=prompt,interactive=!!(process.stdin.isTTY && process.stderr.isTTY),warn=console.error}) {
  if(store.read()) {
    try {
      const result=await account.me(),session=store.read();
      if(session)return {session,account:result.account};
    }
    catch(error) {if(!['UNAUTHORIZED','NOT_AUTHENTICATED','SESSION_EXPIRED'].includes(error.code))throw error;}
  }
  if(!interactive)throw new Error('login required: run vigievuln login in an interactive terminal, then retry');
  warn('Sign in to your Vigie Vuln account. Register: https://www.vigievuln.fr/account');
  const email=await ask('Email: '), password=await ask('Password: ',true);
  const result=await account.login({email,password});
  return {session:store.read(),account:result.account};
}
async function run(args, dependencies={}) {
  const [group,command,...rest]=args;
  if(group==='watch')return require('./cli-watch').runWatch(args.slice(1),{ensureSession:async()=>{
    const store=createAccountSessionStore(),account=createAccountClient({sessionStore:store});
    return (await ensureSignedIn({account,store,...dependencies})).session;
  }});
  if(args.some(a=>a==='--help' || a==='-h') || (group==='auth' && !command)) {
    console.log(group==='auth' ? 'Usage: vigievuln login | logout | whoami\nAliases: auth login | logout | status (also auth whoami).\nLogin stores an account session only; it does not configure proxy keys.\nMissing/expired sessions require login; an interactive terminal can prompt.'
      : 'Usage: vigievuln project status\n       vigievuln project push --file <descriptor> (--name <new project> | --id <existing project>)\nUse watch <dir> --help for local collection and safe project updates.');
    return;
  }
  const store=createAccountSessionStore(),account=createAccountClient({sessionStore:store});
  if(group==='auth') {
    if(rest.length)throw new Error('unexpected authentication option');
    if(['login','status','whoami'].includes(command)) {
      const result=await ensureSignedIn({account,store,...dependencies});console.log(`Signed in as ${result.account.email}.`);return;
    }
    if(command==='logout') {await account.logout();console.log('Signed out.');return;}
    throw new Error('usage: vigievuln auth login|status|logout');
  }
  if(group!=='project')throw new Error('invalid command');
  const opts=parse(rest);
  if(command!=='status' && (command!=='push' || !opts['--file'] || (!!opts['--name'] === !!opts['--id'])))
    throw new Error('usage: vigievuln project push --file <descriptor> (--name <new project> | --id <existing project>)');
  if(command==='status' && Object.keys(opts).length)throw new Error('project status takes no options');
  const {session}=await ensureSignedIn({account,store,...dependencies});
  if(command==='status') {
    const data=await projectRequest('/v1/projects',{session:session.token});
    if(!Array.isArray(data.projects))throw new Error('invalid project service response');
    for(const p of data.projects)console.log(`${p.id}\t${p.name}\trevision ${p.revision}`);
    if(!data.projects.length)console.log('No projects.');return;
  }
  const stat=fs.statSync(opts['--file']);if(!stat.isFile() || stat.size>1900000)throw new Error('invalid or oversized descriptor file');
  let descriptor;try {descriptor=JSON.parse(fs.readFileSync(opts['--file'],'utf8'));}
  catch {throw new Error('unable to read project descriptor as JSON');}
  console.error('Project coordinates and versions will be stored on the service. Review and exclude private packages before uploading.');
  let result;
  if(opts['--name']) result=await createProject({session:session.token,name:opts['--name'],descriptor});
  else {
    const id=opts['--id'];if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))throw new Error('invalid project id');
    const current=await projectRequest(`/v1/projects/${id}`,{session:session.token});
    if(!Number.isSafeInteger(current?.project?.revision))throw new Error('invalid project revision');
    result=await updateProject({session:session.token,id,revision:current.project.revision,descriptor});
  }
  if(!result?.project?.id)throw new Error('invalid project service response');
  console.log(`Project ${result.project.id} saved (revision ${result.project.revision}).`);
}
module.exports={run,ensureSignedIn};
