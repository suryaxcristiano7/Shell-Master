// src/lib/commands/offensive.ts

import { ShellState, CommandResult } from '../shell';
import { 
  findHost, resolveToIp, findWebServer, findWebPage, checkCredentials, 
  findDnsRecords, findWhois, findVulnParam, randomInt, randomMac 
} from '../network';
import { readFile, writeFile, resolvePath, getNode, createDir } from '../vfs';

/** Ensure every segment of a directory path exists (like mkdir -p). */
function ensureDir(state: ShellState, absPath: string): void {
  const parts = absPath.split('/').filter(Boolean);
  let cur = '';
  for (const part of parts) {
    cur += '/' + part;
    const node = getNode(state.vfs, cur);
    if (!node) createDir(state.vfs, cur);
  }
}

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Get an option value: either attached (-pPASS) or as the next argument (-p PASS). */
function opt(args: string[], ...flags: string[]): string | undefined {
  for (const f of flags) {
    const i = args.indexOf(f);
    if (i !== -1 && i + 1 < args.length && !args[i + 1].startsWith('-')) return args[i + 1];
    const attached = args.find(a => a.startsWith(f) && a.length > f.length && !/^\d/.test('') );
    if (attached) return attached.slice(f.length);
  }
  return undefined;
}

function getTarget(args: string[], state: ShellState): string | null {
  // Find the last argument that isn't a flag
  const target = args.findLast(a => !a.startsWith('-'));
  if (!target) return null;
  return resolveToIp(state.network, target);
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const remainingS = s % 60;
  return `${m}:${remainingS.toString().padStart(2, '0')}`;
}

// â”€â”€â”€ Nmap Simulator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export function cmdNmap(args: string[], state: ShellState): CommandResult {
  const targetStr = args.findLast(a => !a.startsWith('-')) || '';
  if (!targetStr) return { output: 'nmap: missing target\n', exitCode: 1 };

  const ip = resolveToIp(state.network, targetStr);
  if (!ip) return { output: `Failed to resolve "${targetStr}".\n`, exitCode: 1 };

  const host = findHost(state.network, ip);
  if (!host || !host.isUp) {
    return { output: `Starting Nmap 7.94 ( https://nmap.org )\nNote: Host seems down.\nNmap done: 1 IP address (0 hosts up) scanned in 2.05 seconds\n`, exitCode: 0 };
  }

  // Parse flags
  const showVersion = args.includes('-sV');
  const showScripts = args.includes('-sC');
  const osDetect = args.includes('-O');
  const allPorts = args.includes('-p-');
  const specificPorts = args.find(a => a.startsWith('-p'))?.slice(2);
  
  let output = `Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-13 10:00 UTC\n`;
  output += `Nmap scan report for ${host.hostname || ip} (${ip})\n`;
  output += `Host is up (${randomInt(1, 50)}ms latency).\n\n`;

  // Filter ports
  let portsToShow = host.ports;
  if (specificPorts) {
    const requested = specificPorts.split(',').map(Number);
    portsToShow = host.ports.filter(p => requested.includes(p.port));
  } else if (!allPorts) {
    // Default top 1000 simulation: just show open ones for simplicity in this demo
    portsToShow = host.ports.filter(p => p.state === 'open' || p.state === 'filtered');
  }

  if (portsToShow.length === 0) {
    output += `Not shown: 1000 filtered tcp ports\nNo open ports found.\n`;
  } else {
    output += `Not shown: ${1000 - portsToShow.length} closed tcp ports\n`;
    output += `PORT     STATE SERVICE       VERSION\n`;
    
    for (const p of portsToShow) {
      let line = `${p.port}/${p.protocol.padEnd(3)} ${p.state.padEnd(7)} ${p.service.padEnd(13)}`;
      if (showVersion && p.version) {
        line += p.version;
      }
      output += line + '\n';
      
      if (showScripts && p.port === 80) {
        output += `|_http-title: Corp Intranet\n`;
        output += `|_http-server-header: Apache/2.4.54 (Ubuntu)\n`;
      }
      if (showScripts && p.port === 22) {
        output += `| ssh-hostkey:\n|   2048 SHA256:xyz... (RSA)\n|_  256 SHA256:abc... (ECDSA)\n`;
      }
    }
  }

  if (osDetect) {
    output += `\nOS detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n`;
    output += `OS details: ${host.os}\n`;
    output += `Network Distance: ${randomInt(1, 5)} hops\n`;
  }

  output += `\nNmap done: 1 IP address (1 host up) scanned in ${randomInt(1, 10)}.42 seconds\n`;
  return { output, exitCode: 0 };
}

// â”€â”€â”€ Hydra Simulator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// Simulated wordlists that exist "inside" rockyou.txt-style files
const SIM_USERS = ['admin', 'root', 'tomcat', 'jdoe', 'ftpuser', 'app', 'hacker'];
const SIM_PASSES = ['password', '123456', 'admin', 'toor', 'abc123', 's3cret', 'letmein',
  'qwerty', 'root', 'ftpuser', 'mysqlroot123', 'shellstrike2026', 'Sup3rS3cr3tP@ss'];

export function cmdHydra(args: string[], state: ShellState): CommandResult {
  // Options: -l user | -L userfile | -p pass | -P passfile | -s port
  const singleUser = opt(args, '-l');
  const userFile = opt(args, '-L');
  const singlePass = opt(args, '-p');
  const passFile = opt(args, '-P');

  const users = singleUser ? [singleUser] : userFile ? SIM_USERS : ['admin'];
  const passes = singlePass ? [singlePass] : passFile ? SIM_PASSES : ['password'];

  // Protocol detection (a bare protocol word like ssh / ftp / mysql, or http-post-form spec)
  const protocolArg = args.find(a =>
    ['ssh', 'ftp', 'http-post-form', 'http-get-form', 'mysql', 'http', 'https'].some(p => a === p || a.startsWith(p + ' ')) ||
    (a.startsWith('/') && a.includes(':')));

  let protocol = 'ssh';
  let path = '';
  if (protocolArg) {
    if (['http-post-form', 'http-get-form', 'http', 'https'].includes(protocolArg)) {
      // Web form attacks: protocol word is separate from the form spec argument
      protocol = 'http';
      const formSpec = args.find(a => a.startsWith('/') && a.includes(':'));
      if (formSpec) path = formSpec.split(':')[0];
    } else if (protocolArg.startsWith('/')) {
      // http form spec given directly: "/login:user=^USER^&pass=^PASS^:F=failed"
      protocol = 'http';
      path = protocolArg.split(':')[0];
    } else {
      protocol = protocolArg.split(' ')[0];
    }
  }

  // Target: the last non-flag argument that is not a protocol word / form spec
  const skip = new Set<string>(['ssh', 'ftp', 'mysql', 'http', 'https', 'http-post-form', 'http-get-form']);
  const candidates = args.filter(a => !a.startsWith('-') && !a.startsWith('/') && !skip.has(a));
  const targetStr = candidates[candidates.length - 1] || '';
  if (!targetStr) return { output: 'Error: No target specified.\n', exitCode: 1 };

  const ip = resolveToIp(state.network, targetStr);
  if (!ip) return { output: `Could not resolve target: ${targetStr}\n`, exitCode: 1 };

  // Port: -s option, else protocol default
  const portArg = opt(args, '-s') || (args.find(a => /^-s\d+$/.test(a))?.slice(2));
  const port = portArg ? parseInt(portArg) : (protocol === 'http' ? 80 : protocol === 'ssh' ? 22 : protocol === 'ftp' ? 21 : 3306);

  let output = `Hydra v9.4 (c) 2023 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and rules anyway).\n\n`;
  output += `[DATA] max 16 tasks per 1 server, overall 16 tasks, ${users.length * passes.length} login tries (l:${users.length}/p:${passes.length}), ~1 try per task\n`;
  output += `[DATA] attacking ${protocol}://${ip}:${port}${path}\n`;

  // Check credentials
  let found = false;
  for (const u of users) {
    for (const p of passes) {
      const res = checkCredentials(state.network, ip, port, protocol, u, p);
      if (res.success) {
        output += `[${protocol}] host: ${ip}   login: ${u}   password: ${p}\n`;
        found = true;
      }
    }
  }

  if (!found) {
    output += `[ERROR] No valid credentials found.\n`;
  }

  output += `1 of 1 target successfully completed, ${found ? 1 : 0} valid password found\n`;
  output += `Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-13 10:05:00\n`;

  return { output, exitCode: found ? 0 : 1 };
}

// â”€â”€â”€ Gobuster Simulator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export function cmdGobuster(args: string[], state: ShellState): CommandResult {
  const urlArg = opt(args, '-u') || (args.find(a => a.startsWith('-u'))?.slice(2));
  if (!urlArg) return { output: 'Error: Please provide the URL (-u)\n', exitCode: 1 };

  // Parse IP from URL
  const match = urlArg.match(/(\d+\.\d+\.\d+\.\d+)/);
  const ip = match ? match[1] : null;
  if (!ip) return { output: `Error: Invalid URL format\n`, exitCode: 1 };

  const portMatch = urlArg.match(/:(\d+)/);
  const port = portMatch ? parseInt(portMatch[1]) : 80;

  const server = findWebServer(state.network, ip, port);
  if (!server) return { output: `Error: Could not connect to ${urlArg}\n`, exitCode: 1 };

  let output = `================================================================\nGobuster v3.6\nby OJ Reeves (@TheColonial) & Tim Morgan (@b0rn2run)\n===============================================================\n`;
  output += `[+] Url         : ${urlArg}\n`;
  output += `[+] Method      : GET\n`;
  output += `[+] Threads     : 10\n`;
  output += `[+] Wordlist    : /usr/share/wordlists/dirb-common.txt\n`;
  output += `===============================================================\n`;

  // Simulate scanning known paths
  const commonPaths = ['admin', 'login', 'backup', 'config', 'api', 'uploads', '.git', 'robots.txt', 'server-status'];
  
  for (const path of commonPaths) {
    const page = findWebPage(state.network, ip, port, '/' + path);
    if (page) {
      const status = page.statusCode;
      const size = page.contentLength;
      const color = status >= 200 && status < 300 ? '\x1b[32m' : status >= 300 && status < 400 ? '\x1b[33m' : '\x1b[31m';
      output += `${color}/${path.padEnd(20)} (Status: ${status}) [Size: ${size}]\x1b[0m\n`;;
    }
  }

  output += `================================================================\nFinished\n===============================================================\n`;
  return { output, exitCode: 0 };
}

// â”€â”€â”€ Sqlmap Simulator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€()•áÁ½ÉÐ™Õ¹Ñ¥½¸µ‘MÅ±µ…À¡…ÉÌèÍÑÉ¥¹mt°ÍÑ…Ñ”èM¡•±±MÑ…Ñ”¤è½µµ…¹‘I•ÍÕ±Ðì(€½¹ÍÐÕÉ±Éœ€ô½ÁÐ¡…ÉÌ°€œµÔœ¤ñð€¡…ÉÌ¹™¥¹¡„€ôø„¹ÍÑ…ÉÑÍ]¥Ñ  œµÔœ¤¤ü¹Í±¥” È¤¤ñð€œœì(€½¹ÍÐÁ…É…µÉœ€ô½ÁÐ¡…ÉÌ°€œ´µ‘…Ñ„œ¤ñð€¡…ÉÌ¹™¥¹¡„€ôø„¹¥¹±Õ‘•Ì œôœ¤¤ü¹ÍÁ±¥Ð œôœ¥lÁt¤ì€¼¼I½Õ Á…ÉÍ¥¹œ(€€(€¥˜€ …ÕÉ±Éœ¤É•ÑÕÉ¸ì½ÕÑÁÕÐè€ÕÍ…”èÍÅ±µ…À€µÔUI0m½ÁÑ¥½¹Íuq¸œ°•á¥Ñ½‘”è€Äôì((€€¼¼M¥µÁ±”¡•ÕÉ¥ÍÑ¥Œè¡•¬¥˜UI0µ…Ñ¡•Ì½ÕÈÙÕ±¸Á…É…µÌ(€½¹ÍÐÙÕ±¸€ôÍÑ…Ñ”¹¹•ÑÝ½É¬¹ÙÕ±¹A…É…µÌ¹™¥¹¡Ø€ôøÕÉ±Éœ¹¥¹±Õ‘•Ì¡Ø¹ÕÉ°¤ñðØ¹ÕÉ°¹¥¹±Õ‘•Ì¡ÕÉ±Éœ¤¤ì(€€(€±•Ð½ÕÑÁÕÐ€ôl©tÍÑ…ÉÑ¥¹œ €ÄÀèÀÀèÀÀ€¼ÈÀÈØ´Àä´ÄÌ½q¹q¹€ì(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÅtm%9=tÑ•ÍÑ¥¹œ½¹¹•Ñ¥½¸Ñ¼Ñ¡”Ñ…É•ÐUI1q¹€ì(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÉtm%9=t¡•­¥¹œ¥˜Ñ¡”Ñ…É•Ð¥ÌÁÉ½Ñ•Ñ•‰äÍ½µ”]¸¸¹q¹€ì(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÍtm%9=t¡ÕÉ¥ÍÑ¥Ì‘•Ñ•Ñ•Ý•ˆÁ…”¥Ì€Á…¡”q¹€ì((€¥˜€ …ÙÕ±¸ñð€…ÙÕ±¸¹ÙÕ±¹•É…‰±”¤ì(€€€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÕtm]I9%9tPÁ…É…µ•Ñ•È€œ‘íÁ…É…µÉœñð€¥ôœ‘½•Ì¹½ÐÍ••´Ñ¼‰”¥¹©•Ñ…‰±•q¹€ìì(€€€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÙtmI%Q%1t…±°Ñ•ÍÑ•Á…É…µ•Ñ•ÉÌ‘¼¹½Ð…ÁÁ•…ÈÑ¼‰”¥¹©•Ñ…‰±”¹q¹€ìì(€€€É•ÑÕÉ¸ì½ÕÑÁÕÐ°•á¥Ñ½‘”è€Àôì(€ô((€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÕtm%9=tÑ•ÍÑ¥¹œ€9‰½½±•…¸µ‰…Í•‰±¥¹€´]!I½È!Y%9±…ÕÍ”q¹€ì(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÙtm%9=tPÁ…É…µ•Ñ•È€œ‘íÙÕ±¸¹Á…É…µôœ…ÁÁ•…ÉÌÑ¼‰”€9‰½½±•…¸µ‰…Í•‰±¥¹€´]!I½È!Y%9±…ÕÍ”œ¥¹©•Ñ…‰±”q¹€ì(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀÝtm%9=tÑ•ÍÑ¥¹œ€5åME0€øô€Ô¸À9•ÉÉ½Èµ‰…Í•€´]!I°!Y%9°=IH	d½ÈI=U@	d±…ÕÍ”€¡1==H¤q¹€ìì(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÀátm%9=tPÁ…É…µ•Ñ•È€œ‘íÙÕ±¸¹Á…É…µôœ¥Ì€5åME0€øô€Ô¸À9•ÉÉ½Èµ‰…Í•€´]!I°!Y%9°=IH	d½ÈI=U@	d±…ÕÍ”€¡1==H¤œ¥¹©•Ñ…‰±”q¹€ìì(€€(€½ÕÑÁÕÐ€¬ôq¸´´µq¹A…É…µ•Ñ•Èè€‘íÙÕ±¸¹Á…É…µô€¡P¥q¸€€€QåÁ”è‰½½±•…¸µ‰…Í•‰±¥¹‘q¸€€€Q¥Ñ±”è9‰½½±•…¸µ‰…Í•‰±¥¹€´]!I½È!Y%9±…ÕÍ•q¸€€€A…å±½…è¥ôÄœ9€ÔàÈäôÔàÈä9€„œô…q¹q¹€ìì(€€(€½ÕÑÁÕÐ€¬ôlÄÀèÀÀèÄÁtm%9=tÑ¡”‰…¬µ•¹	5L¥Ì5åME1q¹€ìì(€½ÕÑÁÕÐ€¬ôÝ•ˆ…ÁÁ±¥…Ñ¥½¸Ñ•¡¹½±½äèA!@€à¸Ä¸È°Á…¡”€È¸Ð¸ÔÑq¹€ì(€½ÕÑÁÕÐ€¬ô‰…¬µ•¹	5Lè5åME0€øô€Ô¸Áq¹€ì(€½ÕÑÁÕÐ€¬ô…Ù…¥±…‰±”‘…Ñ…‰…Í•Ìl‘íÙÕ±¸¹‘‰Ìü¹±•¹Ñ €üü€Éõtéq¹€ì(€™½È€¡½¹ÍÐ½˜ÙÕ±¸¹‘‰Ì€üümt¤½ÕÑÁÕÐ€¬ôl©t€‘í‘õq¹€ì(€½ÕÑÁÕÐ€¬ôl©t•¹‘¥¹œ €ÄÀèÀÀèÄÔ€¼ÈÀÈØ´Àä´ÄÌ½q¹€ìì((€É•ÑÕÉ¸ì½ÕÑÁÕÐ°•á¥Ñ½‘”è€Àôì)ô((¼¼ƒŠRŠRŠR ÕÉ°M¥µÕ±…Ñ½ÈƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ()•áÁ½ÉÐ™Õ¹Ñ¥½¸µ‘ÕÉ°¡…ÉÌèÍÑÉ¥¹mt°ÍÑ…Ñ”èM¡•±±MÑ…Ñ”¤è½µµ…¹‘I•ÍÕ±Ðì(€½¹ÍÐÕÉ±Éœ€ô…ÉÌ¹™¥¹¡„€ôø€…„¹ÍÑ…ÉÑÍ]¥Ñ  œ´œ¤¤ñð€œœìì(€¥˜€ …ÕÉ±Éœ¤É•ÑÕÉ¸ì½ÕÑÁÕÐè€ÕÉ°èÑÉäpÕÉ°€´µ¡•±Ápœ™½Èµ½É”¥¹™½Éµ…Ñ¥½¹q¸œ°•á¥Ñ½‘”è€Äôì((€€¼¼A…ÉÍ”UI0(€±•Ð¥À€ô€œœì(€±•ÐÁ½ÉÐ€ô€àÀì(€±•ÐÁ…Ñ €ô€œ¼œì(€€(€€¼¼!…¹‘±”¡ÑÑÀè¼½%@éA=IP½Á…Ñ (€½¹ÍÐÕÉ±5…Ñ €ôÕÉ±Éœ¹µ…Ñ  ½¡ÑÑÁmÍtüép½p¼¡mq¹t¬¤ üèè¡q¬¤¤ü¡p¼¸¨¤ü¼¤ì(€¥˜€¡ÕÉ±5…Ñ ¤ì(€€€¥À€ôÕÉ±5…Ñ¡lÅtì(€€€Á½ÉÐ€ôÕÉ±5…Ñ¡lÉt€üÁ…ÉÍ•%¹Ð¡ÕÉ±5…Ñ¡lÉt¤€è€àÀì(€€€Á…Ñ €ôÕÉ±5…Ñ¡lÍtñð€œ¼œì(€ô•±Í”ì(€€€€¼¼ÍÍÕµ”¥ÐÌ…¸%@(€€€¥À€ôÕÉ±Éœì(€ô((€½¹ÍÐÁ…”€ô™¥¹‘]•‰A…”¡ÍÑ…Ñ”¹¹•ÑÝ½É¬°¥À°Á½ÉÐ°Á…Ñ ¤ì(€¥˜€ …Á…”¤ì(€€€É•ÑÕÉ¸ì½ÕÑÁÕÐèÕÉ°è€ Ü¤…¥±•Ñ¼½¹¹•ÐÑ¼€‘í¥ÁôÁ½ÉÐ€‘íÁ½ÉÑôè½¹¹•Ñ¥½¸É•™ÕÍ•‘q¹€°•á¥Ñ½‘”è€Üôì(€ô((€±•Ð½ÕÑÁÕÐ€ô€œœì(€¥˜€¡…ÉÌ¹¥¹±Õ‘•Ì œµ¤œ¤ñð…ÉÌ¹¥¹±Õ‘•Ì œµ$œ¤¤ì(€€€€¼¼!•…‘•ÉÌ(€€€½ÕÑÁÕÐ€¬ô!QQ@¼Ä¸Ä€‘íÁ…”¹ÍÑ…ÑÕÍ½‘•ô=-q¹€ì(€€€½ÕÑÁÕÐ€¬ôM•ÉÙ•Èè€‘í™¥¹‘]•‰M•ÉÙ•È¡ÍÑ…Ñ”¹¹•ÑÝ½É¬°¥À°Á½ÉÐ¤ü¹Í•ÉÙ•É!•…‘•Èñð€Á…¡”õq¹€ì(€€€½ÕÑÁÕÐ€¬ô½¹Ñ•¹ÐµQåÁ”è€‘íÁ…”¹½¹Ñ•¹ÑQåÁ•õq¹€ìì(€€€½ÕÑÁÕÐ€¬ô½¹Ñ•¹Ðµ1•¹Ñ è€‘íÁ…”¹½¹Ñ•¹Ñ1•¹Ñ¡õq¹€ì(€€€=‰©•Ð¹•¹ÑÉ¥•Ì¡Á…”¹¡•…‘•ÉÌ¤¹™½É…  ¡m¬°Ùt¤€ôø½ÕÑÁÕÐ€¬ô€‘í­ôè€‘íÙõq¹€¤ìì(€€€½ÕÑÁÕÐ€¬ôq¹€ìì(€ô(€€(€¥˜€ ……ÉÌ¹¥¹±Õ‘•Ì œµ$œ¤¤ì(€€€½ÕÑÁÕÐ€¬ôÁ…”¹‰½‘äì(€ô((€É•ÑÕÉ¸ì½ÕÑÁÕÐ°•á¥Ñ½‘”è€Àôì)ô((¼¼ƒŠRŠRŠR ]•ÐM¥µÕ±…Ñ½ÈƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ()•áÁ½ÉÐ™Õ¹Ñ¥½¸µ‘]ÕÐ¡…ÉÌèÍÑÉ¥¹mt°ÍÑ…Ñ”èM¡•±±MÑ…Ñ”¤è½µµ…¹‘I•ÍÕ±Ðì(€½¹ÍÐÕÉ±Éœ€ô…ÉÌ¹™¥¹¡„€ôø€…„¹ÍÑ…ÉÑÍ]¥Ñ  œ¼œ¤¤ñð€œœìì(€¥˜€ …ÕÉ±Éœ¤É•ÑÕÉ¸ì½ÕÑÁÕÐè€Ý•Ðèµ¥ÍÍ¥¹œUI1q¸œ°•á¥Ñ½‘”è€Äôì((€€¼¼I•ÕÍ”ÕÉ°±½¥ŒÑ¼•Ð½¹Ñ•¹Ð(€½¹ÍÐÕÉ±I•Ì€ôµ‘ÕÉ°¡mÕÉ±Ét°ÍÑ…Ñ”¤ìì(€¥˜€¡ÕÉ±I•Ì¹•á¥Ñ½‘”€„ôô€À¤É•ÑÕÉ¸ÕÉ±I•Ìì((€€¼¼•Ñ•Éµ¥¹”™¥±•¹…µ”(€½¹ÍÐ™¥±•¹…µ”€ôÕÉ±Éœ¹ÍÁ±¥Ð œ¼œ¤¹Á½À ¤ñð€¥¹‘•à¹¡Ñµ°œìì(€½¹ÍÐ…‰ÍA…Ñ €ôÉ•Í½±Ù•A…Ñ ¡ÍÑ…Ñ”¹Ù™Ì¹Ý°™¥±•¹…µ”°ÍÑ…Ñ”¹Ù™Ì¹¡½µ”¤ì(€€(€ÝÉ¥Ñ•¥±”¡ÍÑ…Ñ”¹Ù™Ì°…‰ÍA…Ñ °ÕÉ±I•Ì¹½ÕÑÁÕÐ¤ì(€€(€É•ÑÕÉ¸ì½ÕÑÁÕÐè€´´ÈÀÈØ´Àä´ÄÌ€ÄÀèÀÀèÀÀ´´€€‘íÕÉ±Éõq¹½¹¹•Ñ¥¹œÑ¼€‘íÕÉ±Éô¸¸¸½¹¹•Ñ•¹q¹!QQ@É•ÅÕ•ÍÐÍ•¹Ð°…Ý…¥Ñ¥¹œÉ•ÍÁ½¹Í”¸¸¸€ÈÀÀ=-q¹1•¹Ñ è€‘íÕÉ±I•Ì¹½ÕÑÁÕÐ¹±•¹Ñ¡ômÑ•áÐ½¡Ñµ±uq¹M…Ù¥¹œÑ¼èƒŠ`‘í™¥±•¹…µ•÷Šeq¹q»Š`‘í™¥±•¹…µ•÷ŠdÍ…Ù•l‘íÕÉ±I•Ì¹½ÕÑÁÕÐ¹±•¹Ñ¡ô¼‘íÕÉ±I•Ì¹½ÕÑÁÕÐ¹±•¹Ñ¡õuq¹€°•á¥Ñ½‘”è€Àôì)ô((¼¼ƒŠRŠRŠR 9•Ñ…ÐM¥µÕ±…Ñ½ÈƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ()•áÁ½ÉÐ™Õ¹Ñ¥½¸µ‘9Œ¡…ÉÌèÍÑÉ¥¹mt°ÍÑ…Ñ”èM¡•±±MÑ…Ñ”°ÍÑ‘¥¸èÍÑÉ¥¹œ¤è½µµ…¹‘I•ÍÕ±Ðì(€€¼¼	•ÑÑ•ÈÁ½ÉÐ™¥¹‘¥¹œèÕÍÕ…±±äÑ¡”Í•½¹¹½¸µ™±…œ…Éœ(€½¹ÍÐ¹½¹±…Ì€ô…ÉÌ¹™¥±Ñ•È¡„€ôø€…„¹ÍÑ…ÉÑÍ]¥Ñ  œ´œ¤¤ì(€½¹ÍÐÑ…É•Ð€ô¹½¹±…ÍlÁtì(€½¹ÍÐÁ½ÉÐ€ô¹½¹±…ÍlÅt€üÁ…ÉÍ•%¹Ð¡¹½¹±…ÍlÅt¤€è¹Õ±°ì((€¥˜€ …Ñ…É•Ðñð€…Á½ÉÐ¤É•ÑÕÉ¸ì½ÕÑÁÕÐè€¹Œè¥¹Ù…±¥ÕÍ…•q¸œ°•á¥Ñ½‘”è€Äôì((€½¹ÍÐ¥À€ôÉ•Í½±Ù•Q½%À¡ÍÑ…Ñ”¹¹•ÑÝ½É¬°Ñ…É•Ð¤ì(€¥˜€ …¥À¤É•ÑÕÉ¸ì½ÕÑÁÕÐè¹Œè•Ñ…‘‘É¥¹™¼è9…µ”½ÈÍ•ÉÙ¥”¹½Ð­¹½Ý¹q¹€°•á¥Ñ½‘”è€Äôì((€½¹ÍÐ¡½ÍÐ€ô™¥¹‘!½ÍÐ¡ÍÑ…Ñ”¹¹•ÑÝ½É¬°¥À¤ì(€½¹ÍÐ½Á•¹A½ÉÐ€ô¡½ÍÐü¹Á½ÉÑÌ¹™¥¹¡À€ôøÀ¹Á½ÉÐ€ôôôÁ½ÉÐ€˜˜À¹ÍÑ…Ñ”€ôôô€½Á•¸œ¤ì((€¥˜€ …½Á•¹A½ÉÐ¤ì(€€€É•ÑÕÉ¸ì½ÕÑÁÕÐè¹Œè½¹¹•ÐÑ¼€‘í¥ÁôÁ½ÉÐ€‘íÁ½ÉÑô€¡ÑÀ¤™…¥±•è½¹¹•Ñ¥½¸É•™ÕÍ•‘q¹€°•á¥Ñ½‘”è€Äôì(€ô((€€¼¼%˜±¥ÍÑ•¹¥¹œµ½‘”€ µ°¤°Í¥µÕ±…Ñ”„‰…¹¹•È½È•¡¼(€¥˜€¡…ÉÌ¹¥¹±Õ‘•Ì œµ°œ¤¤ì(€€€É•ÑÕÉ¸ì½ÕÑÁÕÐè€‘í½Á•¹A½ÉÐ¹‰…¹¹•Èñð€œô‘íÍÑ‘¥¹õ€°•á¥Ñ½‘”è€Àôì(€ô((€€¼¼%˜½¹¹•Ñ¥¹œ°Í¡½Ü‰…¹¹•È¥˜…Ù…¥±…‰±”(€É•ÑÕÉ¸ì½ÕÑÁÕÐè€‘í½Á•¹A½ÉÐ¹‰…¹¹•Èñð€œõ€°•á¥Ñ½‘”è€Àôì)ô(