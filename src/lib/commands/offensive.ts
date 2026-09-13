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

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

// ─── Nmap Simulator ──────────────────────────────────────────────────────────

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

// ─── Hydra Simulator ─────────────────────────────────────────────────────────

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

// ─── Gobuster Simulator ───────────────────────────────────────────────────────

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

  let output = `===============================================================\nGobuster v3.6\nby OJ Reeves (@TheColonial) & Tim Morgan (@b0rn2run)\n===============================================================\n`;
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
      output += `${color}/${path.padEnd(20)} (Status: ${status}) [Size: ${size}]\x1b[0m\n`;
    }
  }

  output += `===============================================================\nFinished\n===============================================================\n`;
  return { output, exitCode: 0 };
}

// ─── Sqlmap Simulator ────────────────────────────────────────────────────────

export function cmdSqlmap(args: string[], state: ShellState): CommandResult {
  const urlArg = opt(args, '-u') || (args.find(a => a.startsWith('-u'))?.slice(2)) || '';
  const paramArg = opt(args, '--data') || (args.find(a => a.includes('='))?.split('=')[0]); // Rough parsing
  
  if (!urlArg) return { output: 'usage: sqlmap -u URL [options]\n', exitCode: 1 };

  // Simple heuristic: check if URL matches our vuln params
  const vuln = state.network.vulnParams.find(v => urlArg.includes(v.url) || v.url.includes(urlArg));
  
  let output = `[*] starting @ 10:00:00 /2026-09-13/\n\n`;
  output += `[10:00:01] [INFO] testing connection to the target URL\n`;
  output += `[10:00:02] [INFO] checking if the target is protected by some WAF...\n`;
  output += `[10:00:03] [INFO] heuristics detected web page is 'Apache'\n`;

  if (!vuln || !vuln.vulnerable) {
    output += `[10:00:05] [WARNING] GET parameter '${paramArg || 'id'}' does not seem to be injectable\n`;
    output += `[10:00:06] [CRITICAL] all tested parameters do not appear to be injectable.\n`;
    return { output, exitCode: 0 };
  }

  output += `[10:00:05] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n`;
  output += `[10:00:06] [INFO] GET parameter '${vuln.param}' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable \n`;
  output += `[10:00:07] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'\n`;
  output += `[10:00:08] [INFO] GET parameter '${vuln.param}' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable \n`;
  
  output += `\n---\nParameter: ${vuln.param} (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind - WHERE or HAVING clause\n    Payload: id=1' AND 5829=5829 AND 'a'='a\n\n`;
  
  output += `[10:00:10] [INFO] the back-end DBMS is MySQL\n`;
  output += `web application technology: PHP 8.1.2, Apache 2.4.54\n`;
  output += `back-end DBMS: MySQL >= 5.0\n`;
  output += `available databases [${vuln.dbs?.length ?? 2}]:\n`;
  for (const d of vuln.dbs ?? []) output += `[*] ${d}\n`;
  output += `[*] ending @ 10:00:15 /2026-09-13/\n`;

  return { output, exitCode: 0 };
}

// ─── Curl Simulator ──────────────────────────────────────────────────────────

export function cmdCurl(args: string[], state: ShellState): CommandResult {
  const urlArg = args.find(a => !a.startsWith('-')) || '';
  if (!urlArg) return { output: 'curl: try \'curl --help\' for more information\n', exitCode: 1 };

  // Parse URL
  let ip = '';
  let port = 80;
  let path = '/';
  
  // Handle http://IP:PORT/path
  const urlMatch = urlArg.match(/http[s]?:\/\/([\d.]+)(?::(\d+))?(\/.*)?/);
  if (urlMatch) {
    ip = urlMatch[1];
    port = urlMatch[2] ? parseInt(urlMatch[2]) : 80;
    path = urlMatch[3] || '/';
  } else {
    // Assume it's an IP
    ip = urlArg;
  }

  const page = findWebPage(state.network, ip, port, path);
  if (!page) {
    return { output: `curl: (7) Failed to connect to ${ip} port ${port}: Connection refused\n`, exitCode: 7 };
  }

  let output = '';
  if (args.includes('-i') || args.includes('-I')) {
    // Headers
    output += `HTTP/1.1 ${page.statusCode} OK\n`;
    output += `Server: ${findWebServer(state.network, ip, port)?.serverHeader || 'Apache'}\n`;
    output += `Content-Type: ${page.contentType}\n`;
    output += `Content-Length: ${page.contentLength}\n`;
    Object.entries(page.headers).forEach(([k, v]) => output += `${k}: ${v}\n`);
    output += `\n`;
  }
  
  if (!args.includes('-I')) {
    output += page.body;
  }

  return { output, exitCode: 0 };
}

// ─── Wget Simulator ──────────────────────────────────────────────────────────

export function cmdWget(args: string[], state: ShellState): CommandResult {
  const urlArg = args.find(a => !a.startsWith('-')) || '';
  if (!urlArg) return { output: 'wget: missing URL\n', exitCode: 1 };

  // Reuse curl logic to get content
  const curlRes = cmdCurl([urlArg], state);
  if (curlRes.exitCode !== 0) return curlRes;

  // Determine filename
  const filename = urlArg.split('/').pop() || 'index.html';
  const absPath = resolvePath(state.vfs.cwd, filename, state.vfs.home);
  
  writeFile(state.vfs, absPath, curlRes.output);
  
  return { output: `--2026-09-13 10:00:00--  ${urlArg}\nConnecting to ${urlArg}... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: ${curlRes.output.length} [text/html]\nSaving to: ‘${filename}’\n\n‘${filename}’ saved [${curlRes.output.length}/${curlRes.output.length}]\n`, exitCode: 0 };
}

// ─── Netcat Simulator ─────────────────────────────────────────────────────────

export function cmdNc(args: string[], state: ShellState, stdin: string): CommandResult {
  // Better port finding: usually the second non-flag arg
  const nonFlags = args.filter(a => !a.startsWith('-'));
  const target = nonFlags[0];
  const port = nonFlags[1] ? parseInt(nonFlags[1]) : null;

  if (!target || !port) return { output: 'nc: invalid usage\n', exitCode: 1 };

  const ip = resolveToIp(state.network, target);
  if (!ip) return { output: `nc: getaddrinfo: Name or service not known\n`, exitCode: 1 };

  const host = findHost(state.network, ip);
  const openPort = host?.ports.find(p => p.port === port && p.state === 'open');

  if (!openPort) {
    return { output: `nc: connect to ${ip} port ${port} (tcp) failed: Connection refused\n`, exitCode: 1 };
  }

  // If listening mode (-l), simulate a banner or echo
  if (args.includes('-l')) {
    return { output: `${openPort.banner || ''}${stdin}`, exitCode: 0 };
  }

  // If connecting, show banner if available
  return { output: `${openPort.banner || ''}`, exitCode: 0 };
}

// ─── Ping Simulator ──────────────────────────────────────────────────────────

export function cmdPing(args: string[], state: ShellState): CommandResult {
  const target = args.find(a => !a.startsWith('-')) || '';
  if (!target) return { output: 'ping: usage error: Destination address required\n', exitCode: 1 };

  const ip = resolveToIp(state.network, target);
  if (!ip) return { output: `ping: ${target}: Name or service not known\n`, exitCode: 1 };

  const host = findHost(state.network, ip);
  if (!host || !host.isUp) {
    return { output: `PING ${target} (${ip}) 56(84) bytes of data.\nFrom ${state.vfs.cwd} icmp_seq=1 Destination Host Unreachable\n`, exitCode: 1 };
  }

  let output = `PING ${target} (${ip}) 56(84) bytes of data.\n`;
  for (let i = 1; i <= 4; i++) {
    const time = randomInt(1, 50);
    output += `64 bytes from ${ip}: icmp_seq=${i} ttl=${host.ttl} time=${time}.${randomInt(1, 9)} ms\n`;
  }
  output += `\n--- ${target} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n`;
  
  return { output, exitCode: 0 };
}

// ─── Dig/Nslookup Simulator ──────────────────────────────────────────────────

export function cmdDig(args: string[], state: ShellState): CommandResult {
  const domain = args.find(a => !a.startsWith('-')) || 'corp.local';
  const type = args.find(a => ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA'].includes(a.toUpperCase()))?.toUpperCase() || 'A';

  const records = findDnsRecords(state.network, domain, type);
  
  let output = `; <<>> DiG 9.18.19-1~deb12u1-Debian <<>> ${domain} ${type}\n;; global options: +cmdsubnets\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ${randomInt(1000, 9999)}\n;; flags: qr rd ra; QUERY: 1, ANSWER: ${records.length}, AUTHORITY: 2, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;${domain}.\t\t\tIN\t${type}\n\n;; ANSWER SECTION:\n`;
  
  if (records.length === 0) {
    output += `;; AUTHORITY SECTION:\ncorp.local.\t\t3600\tIN\tSOA\tdc01.corp.local. admin.corp.local. 2026091301 3600 900 604800 86400\n`;
  } else {
    records.forEach(r => {
      output += `${r.name}.\t\t${r.ttl}\tIN\t${r.type}\t${r.value}\n`;
    });
  }
  
  output += `\n;; Query time: ${randomInt(1, 10)} msec\n;; SERVER: 10.10.10.10#53(10.10.10.10) (UDP)\n;; WHEN: Sun Sep 13 10:00:00 UTC 2026\n;; MSG SIZE  rcvd: ${randomInt(50, 200)}\n`;

  return { output, exitCode: 0 };
}

export function cmdNslookup(args: string[], state: ShellState): CommandResult {
  const domain = args[0] || 'corp.local';
  const records = findDnsRecords(state.network, domain, 'A');
  
  let output = `Server:\t\t10.10.10.10\nAddress:\t10.10.10.10#53\n\nNon-authoritative answer:\n`;
  if (records.length > 0) {
    records.forEach(r => {
      output += `Name:\t${r.name}\nAddress: ${r.value}\n`;
    });
  } else {
    output += `*** Can't find ${domain}: No answer\n`;
  }
  
  return { output, exitCode: 0 };
}

// ─── Whois Simulator ─────────────────────────────────────────────────────────

export function cmdWhois(args: string[], state: ShellState): CommandResult {
  const domain = args[0] || 'corp.local';
  const data = findWhois(state.network, domain);
  
  if (!data) return { output: `Whois lookup failed for ${domain}\n`, exitCode: 1 };

  let output = `Domain Name: ${data.domain}\nRegistry Domain ID: \nRegistrar WHOIS Server: whois.internal.registrar\nRegistrar URL: http://www.internal.registrar\nUpdated Date: 2026-01-01T00:00:00Z\nCreation Date: ${data.creationDate}\nRegistry Expiry Date: ${data.expiryDate}\nRegistrar Registration Expiration Date: \nRegistrar: ${data.registrar}\nRegistrar IANA ID: 9999\nRegistrar Abuse Contact Email: abuse@internal.registrar\nRegistrar Abuse Contact Phone: +1.5555555555\nDomain Status: ${data.status.join('\nDomain Status: ')}\nRegistry Registrant ID: \nRegistrant Name: ${data.registrant}\nRegistrant Organization: ${data.registrant}\nRegistrant Street: \nRegistrant City: \nRegistrant State/Province: \nRegistrant Postal Code: \nRegistrant Country: US\nRegistrant Phone: \nRegistrant Email: \nName Server: ${data.nameServers.join('\nName Server: ')}\nDNSSEC: unsigned\n`;
  
  return { output, exitCode: 0 };
}

// ─── Traceroute Simulator ────────────────────────────────────────────────────

export function cmdTraceroute(args: string[], state: ShellState): CommandResult {
  const target = args[0] || '8.8.8.8';
  const ip = resolveToIp(state.network, target) || '8.8.8.8';
  
  let output = `traceroute to ${target} (${ip}), 30 hops max, 60 byte packets\n`;
  const hops = [
    '192.168.1.1',
    '10.0.0.1',
    '172.16.0.1',
    ip
  ];
  
  hops.forEach((hop, i) => {
    const time1 = randomInt(1, 20);
    const time2 = randomInt(1, 20);
    const time3 = randomInt(1, 20);
    output += ` ${i+1}  ${hop} (${hop})  ${time1}.${randomInt(1,9)} ms  ${time2}.${randomInt(1,9)} ms  ${time3}.${randomInt(1,9)} ms\n`;
  });
  
  return { output, exitCode: 0 };
}

// ─── Ifconfig/IP Simulator ────────────────────────────────────────────────────

export function cmdIfconfig(args: string[], state: ShellState): CommandResult {
  let output = `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n        RX packets 12345  bytes 6789012 (6.4 MiB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 6789  bytes 1234567 (1.1 MiB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n        loopback  txqueuelen 1000  (Local Loopback)\n        RX packets 100  bytes 10000 (9.7 KiB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 100  bytes 10000 (9.7 KiB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n`;
  return { output, exitCode: 0 };
}

// ─── Ps/Kill Simulator ────────────────────────────────────────────────────────

export function cmdPs(state: ShellState): CommandResult {
  let output = `  PID TTY          TIME CMD\n    1 ?        00:00:01 systemd\n  420 ?        00:00:00 sshd\n  421 pts/0    00:00:00 bash\n  422 pts/0    00:00:00 ps\n`;
  return { output, exitCode: 0 };
}

export function cmdKill(args: string[], state: ShellState): CommandResult {
  return { output: '', exitCode: 0 }; // Silent success
}

// ─── Sudo Simulator ──────────────────────────────────────────────────────────
// Note: 'sudo' itself is handled specially inside shell.ts (it re-runs the
// command as root). This old implementation is kept only for compatibility.

export function cmdSudo(args: string[], state: ShellState, stdin: string): CommandResult {
  const cmd = args[0];
  if (cmd === 'bash') {
    state.vfs.user = 'root';
    return { output: 'root@shellstrike:/home/hacker# ', exitCode: 0 };
  }
  return { output: `sudo: ${cmd}: command not found\n`, exitCode: 1 };
}

// ─── SSH Simulator ───────────────────────────────────────────────────────────

export function cmdSsh(args: string[], state: ShellState): CommandResult {
  const target = args.filter(a => !a.startsWith('-')).pop() || '';
  if (!target) return { output: 'usage: ssh [-p port] [user@]host\n', exitCode: 1 };

  const m = target.match(/^([^@]+)@(.+)$/);
  const user = m ? m[1] : state.vfs.user;
  const host = m ? m[2] : target;

  const ip = resolveToIp(state.network, host);
  if (!ip) return { output: `ssh: Could not resolve hostname ${host}: Name or service not known\n`, exitCode: 255 };

  const hostEntry = findHost(state.network, ip);
  const sshPort = hostEntry?.ports.find(p => p.port === 22 && p.state === 'open');
  if (!sshPort) return { output: `ssh: connect to host ${ip} port 22: Connection refused\n`, exitCode: 255 };

  const endpoint = state.network.loginEndpoints.find(e => e.hostIp === ip && e.port === 22 && e.protocol === 'ssh');
  const userValid = endpoint?.validCreds.some(c => c.user === user);
  if (!userValid) return { output: `${user}@${ip}: Permission denied (publickey,password).\n`, exitCode: 255 };

  // Valid username — a password is required. Use: sshpass -p <pass> ssh user@host
  return { output: `${user}@${ip}'s password: \nPermission denied, please try again.\n${user}@${ip}: Permission denied (publickey,password).\nHint: non-interactive password auth is done with sshpass -p <password> ssh user@host\n`, exitCode: 255 };
}

export function cmdSshpass(args: string[], state: ShellState): CommandResult {
  // sshpass -p PASS ssh [user@]host
  const pass = opt(args, '-p') || '';
  const sshIdx = args.indexOf('ssh');
  if (sshIdx === -1 || !pass) return { output: 'Usage: sshpass -p <password> ssh [user@]host\n', exitCode: 1 };

  const target = args[sshIdx + 1] || '';
  const m = target.match(/^([^@]+)@(.+)$/);
  const user = m ? m[1] : state.vfs.user;
  const host = m ? m[2] : target;

  const ip = resolveToIp(state.network, host);
  if (!ip) return { output: `ssh: Could not resolve hostname ${host}\n`, exitCode: 255 };

  const hostEntry = findHost(state.network, ip);
  const sshPort = hostEntry?.ports.find(p => p.port === 22 && p.state === 'open');
  if (!sshPort) return { output: `ssh: connect to host ${ip} port 22: Connection refused\n`, exitCode: 255 };

  const res = checkCredentials(state.network, ip, 22, 'ssh', user, pass);
  if (!res.success) {
    return { output: `${user}@${ip}'s password: \n${res.message}\n`, exitCode: 255 };
  }
  return { output: `${user}@${ip}'s password: \nWelcome to ${hostEntry?.hostname || ip}!\nLast login: Sun Sep 13 09:41:03 2026 from 192.168.1.100\n`, exitCode: 0 };
}

// ─── Find/Locate Simulator ────────────────────────────────────────────────────

export function cmdFind(args: string[], state: ShellState): CommandResult {
  const path = args[0] || '.';
  const nameFlagIndex = args.indexOf('-name');
  const pattern = nameFlagIndex !== -1 ? args[nameFlagIndex + 1].replace(/["']/g, '') : '*';
  
  // Very simplified recursive search
  let output = '';
  if (pattern.includes('passwd')) output += '/etc/passwd\n';
  if (pattern.includes('shadow')) output += '/etc/shadow\n';
  if (pattern.includes('.ssh')) output += '/home/hacker/.ssh\n/home/hacker/.ssh/id_rsa\n';
  if (pattern.includes('flag')) output += '/home/hacker/flag.txt\n/root/flag.txt\n';
  if (pattern === '*' || pattern === '*.*' || !pattern) output += `${path}\n${path}/..\n`;
  
  return { output, exitCode: 0 };
}

export function cmdLocate(args: string[], state: ShellState): CommandResult {
  const pattern = args[0] || '';
  let output = '';
  if (pattern.includes('nmap')) output += '/usr/bin/nmap\n/usr/share/nmap\n';
  if (pattern.includes('hydra')) output += '/usr/bin/hydra\n';
  if (pattern.includes('wordlist')) output += '/usr/share/wordlists/rockyou.txt\n';
  return { output, exitCode: 0 };
}

// ─── Archive/Compression Simulator ─────────────────────────────────────────────

export function cmdTar(args: string[], state: ShellState): CommandResult {
  // Supported: tar -czf|-cvf|-cf ARCHIVE FILES...   tar -tf ARCHIVE   tar -xzf ARCHIVE
  const fIdx = args.findIndex(a => /^-[a-zA-Z]*f/.test(a));
  if (fIdx === -1) return { output: 'tar: option requires an argument -- \'f\'\nTry \'tar --help\' for more information.\n', exitCode: 1 };

  const mode = args[fIdx];
  const archive = args[fIdx + 1];
  const files = args.slice(fIdx + 2);
  const archivePath = resolvePath(state.vfs.cwd, archive || '', state.vfs.home);

  if (!archive) return { output: 'tar: missing archive name\n', exitCode: 1 };

  if (mode.includes('c')) {
    if (files.length === 0) return { output: 'tar: You must specify files to archive\n', exitCode: 1 };
    const parts: string[] = [];
    for (const f of files) {
      const fp = resolvePath(state.vfs.cwd, f, state.vfs.home);
      const c = readFile(state.vfs, fp);
      if (c === null) return { output: `tar: ${f}: Cannot stat: No such file or directory\n`, exitCode: 2 };
      parts.push(`# ${f}\n${c}`);
    }
    const content = `[TARBALL ${archive}]\n` + parts.join('\n\n') + '\n';
    writeFile(state.vfs, archivePath, content);
    return { output: `tar: creating ${archive} with ${files.length} file(s)\n`, exitCode: 0 };
  }

  const content = readFile(state.vfs, archivePath);
  if (content === null) return { output: `tar: ${archive}: Cannot open: No such file or directory\n`, exitCode: 2 };

  if (mode.includes('t')) {
    const names = content.split('\n').filter(l => l.startsWith('# ')).map(l => l.slice(2));
    return { output: names.join('\n') + '\n', exitCode: 0 };
  }
  if (mode.includes('x')) {
    return { output: `tar: extracting ${archive}...\n`, exitCode: 0 };
  }
  return { output: `tar: unknown mode\n`, exitCode: 1 };
}

export function cmdGzip(args: string[], state: ShellState): CommandResult {
  return { output: '', exitCode: 0 };
}

// ─── Encoding/Hashing Simulator ───────────────────────────────────────────────

export function cmdBase64(args: string[], state: ShellState, stdin: string): CommandResult {
  const decode = args.includes('-d');
  if (decode) {
    try {
      return { output: atob(stdin.trim()), exitCode: 0 };
    } catch (e) {
      return { output: 'base64: invalid input\n', exitCode: 1 };
    }
  }
  return { output: btoa(stdin.trim()) + '\n', exitCode: 0 };
}

export function cmdHash(args: string[], state: ShellState, stdin: string): CommandResult {
  // Mock hash
  return { output: `${stdin.trim()}  -\n`, exitCode: 0 };
}

// ─── Cron/At Simulator ────────────────────────────────────────────────────────

export function cmdCrontab(args: string[], state: ShellState): CommandResult {
  const cronPath = `/var/spool/cron/crontabs/${state.vfs.user}`;

  if (args.includes('-l')) {
    const content = readFile(state.vfs, cronPath);
    if (content === null) return { output: `no crontab for ${state.vfs.user}\n`, exitCode: 1 };
    return { output: content + '\n', exitCode: 0 };
  }
  if (args.includes('-e')) {
    return { output: 'crontab: no interactive editor in the simulator — create a cron file and run: crontab <file>\n', exitCode: 1 };
  }
  const file = args.find(a => !a.startsWith('-'));
  if (file) {
    const content = readFile(state.vfs, resolvePath(state.vfs.cwd, file, state.vfs.home));
    if (content === null) return { output: `crontab: ${file}: No such file or directory\n`, exitCode: 1 };
    ensureDir(state, '/var/spool/cron/crontabs');
    writeFile(state.vfs, cronPath, content);
    return { output: '', exitCode: 0 };
  }
  return { output: 'usage: crontab [-l | <file>]\n', exitCode: 1 };
}

export function cmdAt(args: string[], state: ShellState): CommandResult {
  return { output: 'warning: commands will be executed using /bin/sh\njob 1 at Sun Sep 13 11:00:00 2026\n', exitCode: 0 };
}

// ─── FTP Simulator ────────────────────────────────────────────────────────────

export function cmdFtp(args: string[], state: ShellState): CommandResult {
  const target = args.filter(a => !a.startsWith('-')).pop() || '';
  const m = target.match(/^([^@]+)@(.+)$/);
  const user = m ? m[1] : 'anonymous';
  const host = m ? m[2] : target;

  const ip = resolveToIp(state.network, host);
  if (!ip) return { output: `ftp: ${host}: Name or service not known\n`, exitCode: 2 };

  const hostEntry = findHost(state.network, ip);
  const ftpPort = hostEntry?.ports.find(p => p.port === 21 && p.state === 'open');
  if (!ftpPort) return { output: `ftp: connect: Connection refused\n`, exitCode: 2 };

  const res = checkCredentials(state.network, ip, 21, 'ftp', user, '');
  if (res.success) {
    return { output: `Connected to ${ip}.\n220 (vsFTPd 3.0.3)\nName (${ip}:hacker): ${user}\n331 Please specify the password.\n230 Login successful.\nftp> `, exitCode: 0 };
  }
  return { output: `Connected to ${ip}.\n220 (vsFTPd 3.0.3)\nName (${ip}:hacker): ${user}\n331 Please specify the password.\n530 Permission denied.\nftp> `, exitCode: 0 };
}
