// src/lib/shell.ts

import { VFSState, createInitialVFS, resolvePath, getNode, readFile, writeFile, createDir, removeNode, moveNode, copyNode, hasPermission } from './vfs';
import { VirtualNetwork, createNetwork, findHost, resolveToIp, findWebServer, findWebPage, checkCredentials, findDnsRecords, findWhois, findVulnParam, randomInt } from './network';
import {
  cmdNmap, cmdHydra, cmdGobuster, cmdSqlmap, cmdCurl, cmdWget, cmdNc,
  cmdPing, cmdDig, cmdNslookup, cmdWhois, cmdTraceroute, cmdIfconfig,
  cmdPs, cmdKill, cmdSudo, cmdFind, cmdLocate, cmdTar, cmdGzip,
  cmdBase64, cmdHash, cmdCrontab, cmdAt, cmdSsh, cmdFtp
} from './commands/offensive';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ShellState {
  vfs: VFSState;
  network: VirtualNetwork;
  env: Record<string, string>;
  history: string[];
  historyIndex: number;
  exitCode: number;
}

export interface CommandResult {
  output: string;
  exitCode: number;
}

// ─── Initialization ─────────────────────────────────────────────────────────

export function createShellState(): ShellState {
  const vfs = createInitialVFS();
  const network = createNetwork();
  
  return {
    vfs,
    network,
    env: {
      HOME: '/home/hacker',
      USER: 'hacker',
      SHELL: '/bin/bash',
      PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      TERM: 'xterm-256color',
      LANG: 'en_US.UTF-8',
      PS1: '\\[\\e[1;32m\\]┌──(\\[\\e[1;34m\\]hacker㉿shellstrike\\[\\e[1;32m\\])-[\\[\\e[0m\\]\\w\\[\\e[1;32m\\]]\\n└─\\[\\e[1;34m\\]$ \\[\\e[0m\\]',
    },
    history: [],
    historyIndex: -1,
    exitCode: 0,
  };
}

// ─── Tokenizer & Parser ─────────────────────────────────────────────────────

interface ParsedCommand {
  cmd: string;
  args: string[];
  redirects: Redirect[];
}

interface Redirect {
  type: 'stdout' | 'stderr' | 'stdin' | 'append';
  target: string; // filename or fd
}

/**
 * Simple tokenizer that respects quotes and pipes.
 * Note: This is a simplified parser for educational purposes.
 * It handles: cmd arg1 "arg with space" > out.txt | grep foo
 */
function tokenize(input: string): { commands: ParsedCommand[] } {
  const commands: ParsedCommand[] = [];
  let currentCmd: ParsedCommand = { cmd: '', args: [], redirects: [] };
  let currentArg = '';
  let inQuote = false;
  let quoteChar = '';
  
  const chars = input.split('');
  
  for (let i = 0; i < chars.length; i++) {
    const char = chars[i];
    const nextChar = chars[i + 1];

    // Handle Quotes
    if ((char === '"' || char === "'") && !inQuote) {
      inQuote = true;
      quoteChar = char;
      continue;
    }
    if (inQuote && char === quoteChar) {
      inQuote = false;
      quoteChar = '';
      continue;
    }
    if (inQuote) {
      currentArg += char;
      continue;
    }

    // Handle Pipe
    if (char === '|') {
      if (currentArg) currentCmd.args.push(currentArg);
      currentArg = '';
      if (currentCmd.cmd) {
        commands.push(currentCmd);
        currentCmd = { cmd: '', args: [], redirects: [] };
      }
      continue;
    }

    // Handle Redirections
    if (char === '>' || char === '<') {
      if (currentArg) currentCmd.args.push(currentArg);
      currentArg = '';
      
      let type: Redirect['type'] = 'stdout';
      let target = '';
      
      if (char === '>') {
        if (nextChar === '>') {
          type = 'append';
          i++; // skip second >
        }
        // Skip spaces after >
        while (i + 1 < chars.length && chars[i+1] === ' ') i++;
        // Read filename
        let j = i + 1;
        while (j < chars.length && chars[j] !== ' ' && chars[j] !== '|') {
          target += chars[j];
          j++;
        }
        i = j - 1;
      } else if (char === '<') {
        type = 'stdin';
        while (i + 1 < chars.length && chars[i+1] === ' ') i++;
        let j = i + 1;
        while (j < chars.length && chars[j] !== ' ' && chars[j] !== '|') {
          target += chars[j];
          j++;
        }
        i = j - 1;
      }
      
      if (target) {
        currentCmd.redirects.push({ type, target });
      }
      continue;
    }

    // Handle Spaces
    if (char === ' ') {
      if (currentArg) {
        if (!currentCmd.cmd) {
          currentCmd.cmd = currentArg;
        } else {
          currentCmd.args.push(currentArg);
        }
        currentArg = '';
      }
      continue;
    }

    currentArg += char;
  }

  // Flush last arg
  if (currentArg) {
    if (!currentCmd.cmd) currentCmd.cmd = currentArg;
    else currentCmd.args.push(currentArg);
  }
  if (currentCmd.cmd) commands.push(currentCmd);

  return { commands };
}

// ─── Command Execution Engine ───────────────────────────────────────────────

export async function executeCommand(input: string, state: ShellState): Promise<CommandResult> {
  const trimmed = input.trim();
  if (!trimmed) return { output: '', exitCode: 0 };

  // Add to history
  state.history.push(trimmed);
  state.historyIndex = state.history.length;

  const { commands } = tokenize(trimmed);
  if (commands.length === 0) return { output: '', exitCode: 0 };

  let previousOutput = '';
  let exitCode = 0;

  // Execute pipeline
  for (let i = 0; i < commands.length; i++) {
    const cmd = commands[i];
    
    // Handle Input Redirection for first command in pipe
    let stdinContent = previousOutput;
    if (i === 0) {
      const stdinRedir = cmd.redirects.find(r => r.type === 'stdin');
      if (stdinRedir) {
        const absPath = resolvePath(state.vfs.cwd, stdinRedir.target, state.vfs.home);
        const content = readFile(state.vfs, absPath);
        if (content === null) {
          return { output: `bash: ${stdinRedir.target}: No such file or directory\n`, exitCode: 1 };
        }
        stdinContent = content;
      }
    } else {
      // For subsequent commands in pipe, stdin is stdout of previous
      stdinContent = previousOutput;
    }

    // Execute single command
    const result = await runSingleCommand(cmd, state, stdinContent);
    exitCode = result.exitCode;
    previousOutput = result.output;

    // Handle Output Redirection for last command in pipe (or only command)
    if (i === commands.length - 1) {
      const stdoutRedir = cmd.redirects.find(r => r.type === 'stdout' || r.type === 'append');
      if (stdoutRedir) {
        const absPath = resolvePath(state.vfs.cwd, stdoutRedir.target, state.vfs.home);
        const append = stdoutRedir.type === 'append';
        
        // Check permissions
        const existing = getNode(state.vfs, absPath);
        if (existing && existing.type === 'dir') {
           return { output: `bash: ${stdoutRedir.target}: Is a directory\n`, exitCode: 1 };
        }
        
        // Write to file
        writeFile(state.vfs, absPath, previousOutput, append);
        previousOutput = ''; // Suppress output to terminal if redirected
      }
    }
  }

  state.exitCode = exitCode;
  return { output: previousOutput, exitCode };
}

async function runSingleCommand(
  cmd: ParsedCommand, 
  state: ShellState, 
  stdin: string
): Promise<CommandResult> {
  
  const { cmd: name, args } = cmd;

  // --- Built-in Commands (JS Implementation) ---
  switch (name) {
    case 'cd': return cmdCd(args, state);
    case 'pwd': return cmdPwd(state);
    case 'ls': return cmdLs(args, state);
    case 'cat': return cmdCat(args, state, stdin);
    case 'echo': return cmdEcho(args, state);
    case 'touch': return cmdTouch(args, state);
    case 'mkdir': return cmdMkdir(args, state);
    case 'rm': return cmdRm(args, state);
    case 'cp': return cmdCp(args, state);
    case 'mv': return cmdMv(args, state);
    case 'chmod': return cmdChmod(args, state);
    case 'chown': return cmdChown(args, state);
    case 'head': return cmdHead(args, state, stdin);
    case 'tail': return cmdTail(args, state, stdin);
    case 'wc': return cmdWc(args, state, stdin);
    case 'grep': return cmdGrep(args, state, stdin);
    case 'sort': return cmdSort(args, state, stdin);
    case 'uniq': return cmdUniq(args, state, stdin);
    case 'cut': return cmdCut(args, state, stdin);
    case 'tr': return cmdTr(args, state, stdin);
    case 'whoami': return cmdWhoami(state);
    case 'id': return cmdId(state);
    case 'uname': return cmdUname(args, state);
    case 'hostname': return cmdHostname(state);
    case 'date': return cmdDate(state);
    case 'env': return cmdEnv(state);
    case 'export': return cmdExport(args, state);
    case 'clear': return { output: '\x1b[2J\x1b[H', exitCode: 0 }; // ANSI clear screen
    case 'history': return cmdHistory(state);
    case 'which': return cmdWhich(args, state);
    case 'type': return cmdType(args, state);
    case 'help': return cmdHelp();
    case 'man': return cmdMan(args, state);
    case 'exit': return { output: 'logout\n', exitCode: 0 };
    
    // --- Offensive Tools (Simulated) ---
    case 'nmap': return cmdNmap(args, state);
    case 'hydra': return cmdHydra(args, state);
    case 'gobuster': return cmdGobuster(args, state);
    case 'sqlmap': return cmdSqlmap(args, state);
    case 'curl': return cmdCurl(args, state);
    case 'wget': return cmdWget(args, state);
    case 'nc': 
    case 'netcat': return cmdNc(args, state, stdin);
    case 'ping': return cmdPing(args, state);
    case 'dig': return cmdDig(args, state);
    case 'nslookup': return cmdNslookup(args, state);
    case 'whois': return cmdWhois(args, state);
    case 'traceroute': return cmdTraceroute(args, state);
    case 'ifconfig': 
    case 'ip': return cmdIfconfig(args, state);
    case 'ps': return cmdPs(state);
    case 'kill': return cmdKill(args, state);
    case 'sudo': return cmdSudo(args, state, stdin);
    case 'find': return cmdFind(args, state);
    case 'locate': return cmdLocate(args, state);
    case 'tar': return cmdTar(args, state);
    case 'gzip': return cmdGzip(args, state);
    case 'base64': return cmdBase64(args, state, stdin);
    case 'md5sum': 
    case 'sha256sum': return cmdHash(args, state, stdin);
    case 'crontab': return cmdCrontab(args, state);
    case 'at': return cmdAt(args, state);
    case 'ssh': return cmdSsh(args, state);
    case 'ftp': return cmdFtp(args, state);
    
    default:
      // Check if it's a script in PATH (simulated)
      if (name.endsWith('.sh') || name.endsWith('.py')) {
         return runScript(name, args, state, stdin);
      }
      return { output: `bash: ${name}: command not found\n`, exitCode: 127 };
  }
}

// ─── Helper: Resolve Path with Tilde ────────────────────────────────────────

function resolve(arg: string, state: ShellState): string {
  return resolvePath(state.vfs.cwd, arg, state.vfs.home);
}

// ─── Command Implementations (Core) ─────────────────────────────────────────

function cmdCd(args: string[], state: ShellState): CommandResult {
  const target = args[0] || '~';
  const absPath = resolve(target, state);
  const node = getNode(state.vfs, absPath);
  
  if (!node) return { output: `bash: cd: ${target}: No such file or directory\n`, exitCode: 1 };
  if (node.type !== 'dir') return { output: `bash: cd: ${target}: Not a directory\n`, exitCode: 1 };
  if (!hasPermission(state.vfs, absPath, 'execute')) return { output: `bash: cd: ${target}: Permission denied\n`, exitCode: 1 };
  
  state.vfs.cwd = absPath;
  return { output: '', exitCode: 0 };
}

function cmdPwd(state: ShellState): CommandResult {
  return { output: state.vfs.cwd + '\n', exitCode: 0 };
}

function cmdLs(args: string[], state: ShellState): CommandResult {
  const showAll = args.includes('-a') || args.includes('-la') || args.includes('-al');
  const longFormat = args.includes('-l') || args.includes('-la') || args.includes('-al');
  const targetArg = args.find(a => !a.startsWith('-')) || '.';
  const absPath = resolve(targetArg, state);
  const node = getNode(state.vfs, absPath);

  if (!node) return { output: `ls: cannot access '${targetArg}': No such file or directory\n`, exitCode: 2 };
  if (node.type !== 'dir') return { output: `${absPath}\n`, exitCode: 0 };

  if (!hasPermission(state.vfs, absPath, 'read')) {
    return { output: `ls: cannot open directory '${targetArg}': Permission denied\n`, exitCode: 1 };
  }

  const entries = Object.entries(node.children);
  if (!showAll) {
    // Filter hidden files unless -a
  }

  let output = '';
  if (longFormat) {
    output += `total ${entries.length}\n`;
    entries.forEach(([name, child]) => {
      if (!showAll && name.startsWith('.')) return;
      const perms = child.type === 'dir' ? 'd' + child.perms.slice(1) : child.perms;
      const size = child.type === 'file' ? child.size.toString().padStart(5) : '4096';
      const date = 'Sep 13 10:00';
      const owner = child.owner.padEnd(8);
      const group = child.group.padEnd(8);
      const color = child.type === 'dir' ? '\x1b[1;34m' : '\x1b[0m';
      const reset = '\x1b[0m';
      output += `${perms} 1 ${owner} ${group} ${size} ${date} ${color}${name}${reset}\n`;
    });
  } else {
    // Simple list
    const names = entries.map(([name]) => name).filter(n => showAll || !n.startsWith('.'));
    // Colorize dirs
    output = names.map(n => {
      const child = node.children[n];
      const isDir = child?.type === 'dir';
      return isDir ? `\x1b[1;34m${n}\x1b[0m` : n;
    }).join('  ') + '\n';
  }

  return { output, exitCode: 0 };
}

function cmdCat(args: string[], state: ShellState, stdin: string): CommandResult {
  if (args.length === 0) {
    // If no args, cat reads stdin (already provided by pipeline logic)
    return { output: stdin, exitCode: 0 };
  }

  let output = '';
  for (const arg of args) {
    if (arg === '-') {
      output += stdin;
      continue;
    }
    const absPath = resolve(arg, state);
    const content = readFile(state.vfs, absPath);
    if (content === null) {
      return { output: `cat: ${arg}: No such file or directory\n`, exitCode: 1 };
    }
    if (!hasPermission(state.vfs, absPath, 'read')) {
      return { output: `cat: ${arg}: Permission denied\n`, exitCode: 1 };
    }
    output += content;
  }
  return { output, exitCode: 0 };
}

function cmdEcho(args: string[], state: ShellState): CommandResult {
  // Basic variable expansion
  let text = args.join(' ');
  // Expand $VAR
  text = text.replace(/\$(\w+)/g, (_, varName) => state.env[varName] || '');
  // Expand ~
  text = text.replace(/~/g, state.vfs.home);
  
  return { output: text + '\n', exitCode: 0 };
}

function cmdTouch(args: string[], state: ShellState): CommandResult {
  if (args.length === 0) return { output: 'touch: missing file operand\n', exitCode: 1 };
  for (const arg of args) {
    const absPath = resolve(arg, state);
    const node = getNode(state.vfs, absPath);
    if (node) {
      // Update mtime (simulated by doing nothing as we don't track real time deeply)
    } else {
      writeFile(state.vfs, absPath, '');
    }
  }
  return { output: '', exitCode: 0 };
}

function cmdMkdir(args: string[], state: ShellState): CommandResult {
  const recursive = args.includes('-p');
  const targets = args.filter(a => !a.startsWith('-'));
  
  for (const target of targets) {
    const absPath = resolve(target, state);
    if (!createDir(state.vfs, absPath)) {
       // Simple error handling for now
       // In a real impl, we'd check if parent exists for non-recursive
       return { output: `mkdir: cannot create directory '${target}': File exists\n`, exitCode: 1 };
    }
  }
  return { output: '', exitCode: 0 };
}

function cmdRm(args: string[], state: ShellState): CommandResult {
  const recursive = args.includes('-r') || args.includes('-rf');
  const force = args.includes('-f') || args.includes('-rf');
  const targets = args.filter(a => !a.startsWith('-'));

  for (const target of targets) {
    const absPath = resolve(target, state);
    const res = removeNode(state.vfs, absPath, recursive);
    if (!res.ok && !force) {
      return { output: `rm: cannot remove '${target}': ${res.error}\n`, exitCode: 1 };
    }
  }
  return { output: '', exitCode: 0 };
}

function cmdCp(args: string[], state: ShellState): CommandResult {
  if (args.length < 2) return { output: 'cp: missing file operand\n', exitCode: 1 };
  const src = resolve(args[0], state);
  const dest = resolve(args[1], state);
  const res = copyNode(state.vfs, src, dest);
  if (!res.ok) return { output: `cp: ${res.error}\n`, exitCode: 1 };
  return { output: '', exitCode: 0 };
}

function cmdMv(args: string[], state: ShellState): CommandResult {
  if (args.length < 2) return { output: 'mv: missing file operand\n', exitCode: 1 };
  const src = resolve(args[0], state);
  const dest = resolve(args[1], state);
  const res = moveNode(state.vfs, src, dest);
  if (!res.ok) return { output: `mv: ${res.error}\n`, exitCode: 1 };
  return { output: '', exitCode: 0 };
}

function cmdChmod(args: string[], state: ShellState): CommandResult {
  if (args.length < 2) return { output: 'chmod: missing operand\n', exitCode: 1 };
  const mode = args[0];
  const target = resolve(args[1], state);
  const node = getNode(state.vfs, target);
  
  if (!node) return { output: `chmod: cannot access '${args[1]}': No such file or directory\n`, exitCode: 1 };
  if (state.vfs.user !== 'root' && node.owner !== state.vfs.user) {
    return { output: `chmod: changing permissions of '${args[1]}': Operation not permitted\n`, exitCode: 1 };
  }

  // Simplified chmod: just set the perms string directly if it looks valid
  // In a real impl, we'd parse u+x, 755, etc.
  if (/^[drwx-]{10}$/.test(mode)) {
     node.perms = mode;
  } else if (/^\d{3,4}$/.test(mode)) {
     // Convert octal to rwx string (simplified)
     // This is complex to implement fully, so we'll just accept valid strings for now
     // or mock it. For this demo, let's assume user types full string or we ignore.
     // Let's do a basic mapping for common ones.
     const map: Record<string, string> = {
       '777': '-rwxrwxrwx', '755': '-rwxr-xr-x', '644': '-rw-r--r--', '600': '-rw-------',
       '700': '-rwx------', '444': '-r--r--r--'
     };
     if (map[mode]) node.perms = map[mode];
     else return { output: `chmod: invalid mode '${mode}'\n`, exitCode: 1 };
  } else {
     return { output: `chmod: invalid mode '${mode}'\n`, exitCode: 1 };
  }
  
  return { output: '', exitCode: 0 };
}

function cmdChown(args: string[], state: ShellState): CommandResult {
  if (args.length < 2) return { output: 'chown: missing operand\n', exitCode: 1 };
  if (state.vfs.user !== 'root') return { output: `chown: changing ownership of '${args[1]}': Operation not permitted\n`, exitCode: 1 };
  
  const [owner, target] = args;
  const absPath = resolve(target, state);
  const node = getNode(state.vfs, absPath);
  if (!node) return { output: `chown: cannot access '${target}': No such file or directory\n`, exitCode: 1 };
  
  node.owner = owner;
  return { output: '', exitCode: 0 };
}

// --- Text Processing ---

function cmdHead(args: string[], state: ShellState, stdin: string): CommandResult {
  const n = parseInt(args.find(a => a.startsWith('-n'))?.slice(2) || '10');
  const lines = stdin.split('\n');
  return { output: lines.slice(0, n).join('\n') + (lines.length > n ? '\n' : ''), exitCode: 0 };
}

function cmdTail(args: string[], state: ShellState, stdin: string): CommandResult {
  const n = parseInt(args.find(a => a.startsWith('-n'))?.slice(2) || '10');
  const lines = stdin.split('\n');
  // Remove last empty line if present
  if (lines[lines.length-1] === '') lines.pop();
  return { output: lines.slice(-n).join('\n') + '\n', exitCode: 0 };
}

function cmdWc(args: string[], state: ShellState, stdin: string): CommandResult {
  const lines = stdin.split('\n').length - 1;
  const words = stdin.trim().split(/\s+/).filter(Boolean).length;
  const chars = stdin.length;
  return { output: `  ${lines}  ${words} ${chars}\n`, exitCode: 0 };
}

function cmdGrep(args: string[], state: ShellState, stdin: string): CommandResult {
  if (args.length === 0) return { output: 'Usage: grep PATTERN [FILE...]\n', exitCode: 1 };
  const pattern = args[0];
  const ignoreCase = args.includes('-i');
  const invert = args.includes('-v');
  const count = args.includes('-c');
  
  // If file args provided, read them. Else use stdin.
  let text = stdin;
  const files = args.filter(a => !a.startsWith('-') && a !== pattern);
  
  if (files.length > 0) {
    text = '';
    for (const f of files) {
      const absPath = resolve(f, state);
      const content = readFile(state.vfs, absPath);
      if (content) text += content;
    }
  }

  const regex = new RegExp(pattern, ignoreCase ? 'i' : '');
  const matchingLines = text.split('\n').filter(line => regex.test(line) !== invert);
  
  if (count) {
    return { output: `${matchingLines.length}\n`, exitCode: matchingLines.length > 0 ? 0 : 1 };
  }
  
  return { output: matchingLines.join('\n') + (matchingLines.length ? '\n' : ''), exitCode: matchingLines.length ? 0 : 1 };
}

function cmdSort(args: string[], state: ShellState, stdin: string): CommandResult {
  const unique = args.includes('-u');
  const reverse = args.includes('-r');
  let lines = stdin.split('\n').filter(l => l !== '');
  
  lines.sort((a, b) => reverse ? b.localeCompare(a) : a.localeCompare(b));
  if (unique) lines = [...new Set(lines)];
  
  return { output: lines.join('\n') + '\n', exitCode: 0 };
}

function cmdUniq(args: string[], state: ShellState, stdin: string): CommandResult {
  const lines = stdin.split('\n').filter(l => l !== '');
  const unique = lines.filter((line, i) => i === 0 || line !== lines[i-1]);
  return { output: unique.join('\n') + '\n', exitCode: 0 };
}

function cmdCut(args: string[], state: ShellState, stdin: string): CommandResult {
  const delimArg = args.find(a => a.startsWith('-d'));
  const delim = delimArg ? delimArg.slice(2) : '\t';
  const fieldsArg = args.find(a => a.startsWith('-f'));
  if (!fieldsArg) return { output: 'cut: you must specify a list of bytes\n', exitCode: 1 };
  
  const fieldIndices = fieldsArg.slice(2).split(',').map(s => parseInt(s) - 1);
  
  const lines = stdin.split('\n').filter(l => l !== '');
  const output = lines.map(line => {
    const parts = line.split(delim);
    return fieldIndices.map(i => parts[i] || '').join(delim);
  }).join('\n') + '\n';
  
  return { output, exitCode: 0 };
}

function cmdTr(args: string[], state: ShellState, stdin: string): CommandResult {
  if (args.length < 2) return { output: 'tr: missing operand\n', exitCode: 1 };
  const set1 = args[0];
  const set2 = args[1];
  
  // Simple 1:1 replacement
  let output = stdin;
  for (let i = 0; i < set1.length; i++) {
    const c1 = set1[i];
    const c2 = set2[i] || set2[set2.length - 1]; // Repeat last char if set2 is shorter
    output = output.split(c1).join(c2);
  }
  
  return { output, exitCode: 0 };
}

// --- System Info ---

function cmdWhoami(state: ShellState): CommandResult {
  return { output: state.vfs.user + '\n', exitCode: 0 };
}

function cmdId(state: ShellState): CommandResult {
  return { output: `uid=1000(${state.vfs.user}) gid=1000(${state.vfs.user}) groups=1000(${state.vfs.user}),27(sudo)\n`, exitCode: 0 };
}

function cmdUname(args: string[], state: ShellState): CommandResult {
  if (args.includes('-a')) {
    return { output: 'Linux shellstrike 5.15.0-84-generic #93-Ubuntu SMP Fri Aug 25 16:54:01 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux\n', exitCode: 0 };
  }
  return { output: 'Linux\n', exitCode: 0 };
}

function cmdHostname(state: ShellState): CommandResult {
  return { output: 'shellstrike\n', exitCode: 0 };
}

function cmdDate(state: ShellState): CommandResult {
  return { output: 'Sun Sep 13 10:00:00 UTC 2026\n', exitCode: 0 };
}

function cmdEnv(state: ShellState): CommandResult {
  return { output: Object.entries(state.env).map(([k,v]) => `${k}=${v}`).join('\n') + '\n', exitCode: 0 };
}

function cmdExport(args: string[], state: ShellState): CommandResult {
  if (args.length === 0) return cmdEnv(state);
  const [key, ...valParts] = args[0].split('=');
  const val = valParts.join('=');
  state.env[key] = val;
  return { output: '', exitCode: 0 };
}

function cmdHistory(state: ShellState): CommandResult {
  return { output: state.history.map((h, i) => `  ${i+1}  ${h}`).join('\n') + '\n', exitCode: 0 };
}

function cmdWhich(args: string[], state: ShellState): CommandResult {
  if (args.length === 0) return { output: 'usage: which [-a] name ...\n', exitCode: 1 };
  const name = args[0];
  // Check builtins
  const builtins = ['cd', 'pwd', 'ls', 'cat', 'echo', 'touch', 'mkdir', 'rm', 'cp', 'mv', 'chmod', 'chown', 'head', 'tail', 'wc', 'grep', 'sort', 'uniq', 'cut', 'tr', 'whoami', 'id', 'uname', 'hostname', 'date', 'env', 'export', 'clear', 'history', 'which', 'type', 'help', 'man', 'exit'];
  if (builtins.includes(name)) return { output: `/usr/bin/${name}\n`, exitCode: 0 };
  
  // Check PATH (simulated)
  const paths = state.env.PATH.split(':');
  for (const p of paths) {
    const absPath = p + '/' + name;
    if (getNode(state.vfs, absPath)) return { output: absPath + '\n', exitCode: 0 };
  }
  
  return { output: `which: no ${name} in (${state.env.PATH})\n`, exitCode: 1 };
}

function cmdType(args: string[], state: ShellState): CommandResult {
  if (args.length === 0) return { output: 'usage: type [-afptP] name ...\n', exitCode: 1 };
  const name = args[0];
  const builtins = ['cd', 'pwd', 'ls', 'cat', 'echo', 'touch', 'mkdir', 'rm', 'cp', 'mv', 'chmod', 'chown', 'head', 'tail', 'wc', 'grep', 'sort', 'uniq', 'cut', 'tr', 'whoami', 'id', 'uname', 'hostname', 'date', 'env', 'export', 'clear', 'history', 'which', 'type', 'help', 'man', 'exit'];
  if (builtins.includes(name)) return { output: `${name} is a shell builtin\n`, exitCode: 0 };
  return { output: `${name} is /usr/bin/${name}\n`, exitCode: 0 };
}

function cmdHelp(): CommandResult {
  return { output: `GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type 'help' to see this list.
Type 'help name' to find out more about the function 'name'.
Use 'info bash' to find out more about the shell in general.
Use 'man -k' or 'info' to find out more about commands not in this list.

A star (*) next to a name means that the command is disabled.

 job_spec [&]                            history [-c] [-d offset] [n] or hist>
 (( expression ))                        if COMMANDS; then COMMANDS; [ elif C>
 . filename [arguments]                  jobs [-lnprs] [jobspec ...] or jobs >
 :                                       kill [-s sigspec | -n signum | -sigs>
 [ arg... ]                              let arg [arg ...]
 [[ expression ]]                        local [option] name[=value] ...
 alias [-p] [name[=value] ... ]          logout [n]
 bg [job_spec ...]                       mapfile [-d delim] [-n count] [-O or>
 bind [-lpsvPSVX] [-m keymap] [-f file>  popd [-n] [+N | -N]
 break [n]                               printf [-v var] format [arguments]
 builtin [shell-builtin [arg ...]        pushd [-n] [+N | -N | dir]
 caller [expr]                           pwd [-LPW]
 case WORD in [PATTERN [| PATTERN]...)>  read [-ers] [-a array] [-d delim] [->
 cd [-L|[-P [-e]] [-@]] [dir]            readarray [-n count] [-O origin] [-s>
 command [-pVv] command [arg ...]        readonly [-aAfF] [name[=value] ...] o>
 compgen [-abcdefgjksuv] [-o option] [>  return [n]
 complete [-abcdefgjksuv] [-pr] [-DEI]>  select NAME [in WORDS ... ;] do COMM>
 compopt [-o] [-D] [-I] [-E] [-n name]>  set [-abefhkmnptuvxBCHP] [-o option->
 continue [n]                            shift [n]
 coproc [NAME] command [redirections]    shopt [-pqs] [-o optname ...]
 declare [-aAfFgiIlnrtux] [-p [name[=>  source filename [arguments]
 dirs [-clpv] [+N | -N]                  suspend [-f]
 disown [-h] [-ar] [jobspec ... | pid >  test [expr]
 echo [-neE] [arg ...]                   time [-p] pipeline
 enable [-a] [-dnps] [-f filename] [na>  times
 eval [arg ...]                          trap [-lp] [[arg] signal_spec ...]
 exec [-cl] [-a name] [command [argume>  true
 exit [n]                                type [-afptP] name [name ...]
 export [-fn] [name[=value] ...] or ex>  typeset [-aAfFgiIlnrtux] [-p] name[=>
 false                                   ulimit [-SHabcdefiklmnpqrstuvxPT] [l>
 fc [-e ename] [-lnr] [first] [last] o>  umask [-p] [-S] [mode]
 fg [job_spec]                          unalias [-a] name [name ...]
 for NAME [in WORDS ... ] ; do COMMAND>  unset [-f] [-v] [-n] [name ...]
 for (( exp1; exp2; exp3 )); do COMMAN>  until COMMANDS; do COMMANDS; done
 function name { COMMANDS ; } or name >  variables - Names and meanings of so>
 getopts optstring name [arg ...]        wait [-fn] [-p var] [id ...]
 hash [-lr] [-p pathname] [-dt] [name >  while COMMANDS; do COMMANDS; done
 help [-dms] [pattern ...]               { COMMANDS ; }
`, exitCode: 0 };
}

function cmdMan(args: string[], state: ShellState): CommandResult {
  if (args.length === 0) return { output: 'What manual page do you want?\n', exitCode: 1 };
  return { output: `No manual entry for ${args[0]}\n`, exitCode: 1 };
}

// ─── Script Runner (Simulated) ──────────────────────────────────────────────

async function runScript(name: string, args: string[], state: ShellState, stdin: string): Promise<CommandResult> {
  const absPath = resolve(name, state);
  const content = readFile(state.vfs, absPath);
  if (!content) return { output: `bash: ${name}: No such file or directory\n`, exitCode: 127 };
  
  // Very naive script runner: just echo that it ran
  // In a real app, you'd parse bash syntax here or use a library like bashjs
  return { output: `[+] Running script ${name}...\n[+] Done.\n`, exitCode: 0 };
}

// ─── Export for React Component ─────────────────────────────────────────────

export { 
  cmdNmap, cmdHydra, cmdGobuster, cmdSqlmap, cmdCurl, cmdWget, cmdNc, 
  cmdPing, cmdDig, cmdNslookup, cmdWhois, cmdTraceroute, cmdIfconfig, 
  cmdPs, cmdKill, cmdSudo, cmdFind, cmdLocate, cmdTar, cmdGzip, 
  cmdBase64, cmdHash, cmdCrontab, cmdAt, cmdSsh, cmdFtp 
} from './commands/offensive';
