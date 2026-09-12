// src/lib/vfs.ts

// ─── Types ───────────────────────────────────────────────────────────────────

export interface VFile {
  type: 'file';
  content: string;
  perms: string;   // e.g., '-rw-r--r--'
  owner: string;
  group: string;
  size: number;
  mtime: Date;
}

export interface VDir {
  type: 'dir';
  children: Record<string, VNode>;
  perms: string;   // e.g., 'drwxr-xr-x'
  owner: string;
  group: string;
  mtime: Date;
}

export type VNode = VFile | VDir;

export interface VFSState {
  root: VDir;
  cwd: string;       // current working directory absolute path
  user: string;      // current user
  home: string;      // home directory path
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function now(): Date {
  return new Date('2026-09-13T10:00:00Z');
}

function mkfile(content: string, perms = '-rw-r--r--', owner = 'root', group = 'root'): VFile {
  return { type: 'file', content, perms, owner, group, size: content.length, mtime: now() };
}

function mkdir(children: Record<string, VNode> = {}, perms = 'drwxr-xr-x', owner = 'root', group = 'root'): VDir {
  return { type: 'dir', children, perms, owner, group, mtime: now() };
}

// ─── Initial Filesystem (Kali-like layout) ──────────────────────────────────

export function createInitialVFS(): VFSState {
  const root: VDir = mkdir({
    'bin': mkdir({
      'bash':    mkfile('#!/bin/bash\n[ELF BINARY]', '-rwxr-xr-x'),
      'cat':     mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'ls':      mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'grep':    mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'chmod':   mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'cp':      mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'mv':      mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'rm':      mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'mkdir':   mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      'echo':    mkfile('[BUILTIN]'),
      'pwd':     mkfile('[BUILTIN]'),
    }),
    'etc': mkdir({
      'passwd': mkfile(
        'root:x:0:0:root:/root:/bin/bash\n' +
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' +
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n' +
        'hacker:x:1000:1000:Hacker,,,:/home/hacker:/bin/bash\n' +
        'sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n',
        '-rw-r--r--', 'root', 'root'
      ),
      'shadow': mkfile(
        'root:$6$rounds=5000$saltsalt$hashhashhashhashhashhashhashhashhashhashhas:19200:0:99999:7:::\n' +
        'hacker:$6$rounds=5000$pepperpe$anotherhashanotherhashanotherhashanotherha:19200:0:99999:7:::\n',
        '-rw-r-----', 'root', 'shadow'
      ),
      'hosts': mkfile(
        '127.0.0.1\tlocalhost\n' +
        '127.0.1.1\tshellstrike\n' +
        '10.10.10.5\ttarget.corp.local\n' +
        '10.10.10.10\tdc01.corp.local\n',
        '-rw-r--r--', 'root', 'root'
      ),
      'hostname': mkfile('shellstrike\n', '-rw-r--r--'),
      'os-release': mkfile(
        'PRETTY_NAME="Kali GNU/Linux Rolling"\n' +
        'NAME="Kali GNU/Linux"\n' +
        'ID=kali\n' +
        'VERSION="2026.3"\n' +
        'HOME_URL="https://www.kali.org/"\n',
        '-rw-r--r--'
      ),
      'sudoers': mkfile(
        '# /etc/sudoers\nroot ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n',
        '-r--r-----', 'root', 'root'
      ),
    }),
    'home': mkdir({
      'hacker': mkdir({
        '.bashrc': mkfile(
          '# ~/.bashrc\n' +
          'export PS1="\\[\\e[1;32m\\]┌──(\\[\\e[1;34m\\]hacker㉿shellstrike\\[\\e[1;32m\\])-[\\[\\e[0m\\]\\w\\[\\e[1;32m\\]]\\n└─\\[\\e[1;34m\\]$ \\[\\e[0m\\]"\n' +
          'alias ll="ls -la"\n' +
          'alias la="ls -A"\n' +
          'alias c="clear"\n',
          '-rw-r--r--', 'hacker', 'hacker'
        ),
        '.bash_history': mkfile(
          'whoami\nid\nls -la\ncat /etc/passwd\n',
          '-rw-------', 'hacker', 'hacker'
        ),
        'notes.txt': mkfile(
          '=== RECON NOTES ===\n' +
          '- Target: target.corp.local (10.10.10.5)\n' +
          '- Ports seen: 22, 80, 443, 8080\n' +
          '- Admin panel might be on 8080\n' +
          '- Try default creds: admin/admin, admin/password\n' +
          '\n=== TODO ===\n' +
          '- Run gobuster on port 80\n' +
          '- Check for SQLi on login form\n',
          '-rw-r--r--', 'hacker', 'hacker'
        ),
        'tools': mkdir({
          'recon.sh': mkfile(
            '#!/bin/bash\n# Quick recon script\necho "[*] Starting recon..."\nnmap -sC -sV $1\n',
            '-rwxr-xr-x', 'hacker', 'hacker'
          ),
        }, 'drwxr-xr-x', 'hacker', 'hacker'),
        'Desktop': mkdir({}, 'drwxr-xr-x', 'hacker', 'hacker'),
        'Documents': mkdir({}, 'drwxr-xr-x', 'hacker', 'hacker'),
        'Downloads': mkdir({}, 'drwxr-xr-x', 'hacker', 'hacker'),
      }, 'drwx------', 'hacker', 'hacker'),
    }),
    'root': mkdir({}, 'drwx------', 'root', 'root'),
    'tmp': mkdir({
      'exploit.py': mkfile(
        '#!/usr/bin/env python3\n# Placeholder exploit\nimport sys\nprint("[+] Exploit loaded")\n',
        '-rw-r--r--', 'hacker', 'hacker'
      ),
    }, 'drwxrwxrwt', 'root', 'root'),
    'var': mkdir({
      'log': mkdir({
        'auth.log': mkfile(
          'Sep 13 08:01:22 shellstrike sshd[1234]: Accepted password for hacker from 192.168.1.100 port 52413 ssh2\n' +
          'Sep 13 08:05:11 shellstrike sudo: hacker : TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash\n' +
          'Sep 13 09:12:44 shellstrike sshd[1299]: Failed password for root from 10.10.10.99 port 44312 ssh2\n',
          '-rw-r-----', 'root', 'adm'
        ),
        'syslog': mkfile(
          'Sep 13 07:00:01 shellstrike systemd[1]: Started Daily apt download activities.\n' +
          'Sep 13 08:00:00 shellstrike CRON[1100]: (root) CMD (/usr/bin/apt-get update -q)\n',
          '-rw-r-----', 'root', 'adm'
        ),
      }),
      'www': mkdir({
        'html': mkdir({
          'index.html': mkfile(
            '<!DOCTYPE html>\n<html><head><title>Corp Intranet</title></head>\n' +
            '<body><h1>Welcome to Corp</h1><a href="/admin">Admin</a></body></html>\n',
            '-rw-r--r--', 'www-data', 'www-data'
          ),
          'robots.txt': mkfile(
            'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /api/\n',
            '-rw-r--r--', 'www-data', 'www-data'
          ),
        }, 'drwxr-xr-x', 'www-data', 'www-data'),
      }),
    }),
    'usr': mkdir({
      'bin': mkdir({
        'python3': mkfile('[ELF BINARY]', '-rwxr-xr-x'),
        'nmap':    mkfile('[ELF BINARY]', '-rwxr-xr-x'),
        'hydra':   mkfile('[ELF BINARY]', '-rwxr-xr-x'),
        'gobuster': mkfile('[ELF BINARY]', '-rwxr-xr-x'),
        'sqlmap':  mkfile('[PYTHON SCRIPT]', '-rwxr-xr-x'),
        'curl':    mkfile('[ELF BINARY]', '-rwxr-xr-x'),
        'wget':    mkfile('[ELF BINARY]', '-rwxr-xr-x'),
        'nc':      mkfile('[ELF BINARY]', '-rwxr-xr-x'),
      }),
      'share': mkdir({
        'wordlists': mkdir({
          'rockyou.txt': mkfile('[BINARY DATA - 14,341,564 lines]\npassword\n123456\n12345678\nqwerty\nadmin\nletmein\nwelcome\nmonkey\ndragon\nmaster\n', '-rw-r--r--'),
          'dirb-common.txt': mkfile('admin\nlogin\nbackup\nconfig\ntest\nuploads\nimages\napi\nv1\nv2\n.htaccess\n.git\nwp-admin\nphpmyadmin\nserver-status\n', '-rw-r--r--'),
        }),
      }),
    }),
    'opt': mkdir({}, 'drwxr-xr-x'),
  });

  return {
    root,
    cwd: '/home/hacker',
    user: 'hacker',
    home: '/home/hacker',
  };
}

// ─── Path Resolution ────────────────────────────────────────────────────────

/**
 * Resolves any path (relative, absolute, ~, ..) into a clean absolute path.
 * e.g., resolve('/home/hacker', '../root') → '/root'
 * e.g., resolve('/home/hacker', '~/tools') → '/home/hacker/tools'
 */
export function resolvePath(cwd: string, inputPath: string, home: string): string {
  let p = inputPath;

  // Handle tilde expansion
  if (p === '~' || p.startsWith('~/')) {
    p = home + p.slice(1);
  }

  // If not absolute, prepend cwd
  if (!p.startsWith('/')) {
    p = cwd + '/' + p;
  }

  // Split and resolve . and ..
  const parts = p.split('/').filter(Boolean);
  const resolved: string[] = [];

  for (const part of parts) {
    if (part === '.') continue;
    if (part === '..') {
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }

  return '/' + resolved.join('/');
}

// ─── Node Access ─────────────────────────────────────────────────────────────

/**
 * Gets a node at an absolute path. Returns undefined if not found.
 */
export function getNode(state: VFSState, absPath: string): VNode | undefined {
  if (absPath === '/') return state.root;

  const parts = absPath.split('/').filter(Boolean);
  let current: VNode = state.root;

  for (const part of parts) {
    if (current.type !== 'dir') return undefined;
    if (!(part in current.children)) return undefined;
    current = current.children[part];
  }

  return current;
}

/**
 * Gets the parent directory and the basename of a path.
 */
function getParentAndName(state: VFSState, absPath: string): { parent: VDir | undefined; name: string } {
  const parts = absPath.split('/').filter(Boolean);
  const name = parts.pop() || '';
  const parentPath = '/' + parts.join('/');
  const parent = getNode(state, parentPath);
  return {
    parent: parent?.type === 'dir' ? parent : undefined,
    name,
  };
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function readFile(state: VFSState, absPath: string): string | null {
  const node = getNode(state, absPath);
  if (!node || node.type !== 'file') return null;
  return node.content;
}

export function writeFile(state: VFSState, absPath: string, content: string, append = false): boolean {
  const existing = getNode(state, absPath);

  if (existing && existing.type === 'dir') return false;

  if (existing && existing.type === 'file') {
    if (append) {
      existing.content += content;
      existing.size = existing.content.length;
    } else {
      existing.content = content;
      existing.size = content.length;
    }
    existing.mtime = now();
    return true;
  }

  // Create new file
  const { parent, name } = getParentAndName(state, absPath);
  if (!parent || !name) return false;

  parent.children[name] = mkfile(content, '-rw-r--r--', state.user, state.user);
  return true;
}

export function createDir(state: VFSState, absPath: string): boolean {
  const existing = getNode(state, absPath);
  if (existing) return false;

  const { parent, name } = getParentAndName(state, absPath);
  if (!parent || !name) return false;

  parent.children[name] = mkdir({}, 'drwxr-xr-x', state.user, state.user);
  return true;
}

export function removeNode(state: VFSState, absPath: string, recursive = false): { ok: boolean; error?: string } {
  if (absPath === '/') return { ok: false, error: 'cannot remove /' };

  const node = getNode(state, absPath);
  if (!node) return { ok: false, error: 'No such file or directory' };

  if (node.type === 'dir' && Object.keys(node.children).length > 0 && !recursive) {
    return { ok: false, error: 'Directory not empty' };
  }

  const { parent, name } = getParentAndName(state, absPath);
  if (!parent || !name) return { ok: false, error: 'cannot remove' };

  delete parent.children[name];
  return { ok: true };
}

export function moveNode(state: VFSState, srcAbs: string, destAbs: string): { ok: boolean; error?: string } {
  const srcNode = getNode(state, srcAbs);
  if (!srcNode) return { ok: false, error: `cannot stat '${srcAbs}': No such file or directory` };

  const destNode = getNode(state, destAbs);

  // If destination is a directory, move inside it
  if (destNode && destNode.type === 'dir') {
    const srcName = srcAbs.split('/').filter(Boolean).pop() || '';
    destNode.children[srcName] = srcNode;
  } else {
    // Destination is a file path or doesn't exist
    const { parent, name } = getParentAndName(state, destAbs);
    if (!parent || !name) return { ok: false, error: 'invalid destination' };
    parent.children[name] = srcNode;
  }

  // Remove from source
  const srcParent = getParentAndName(state, srcAbs);
  if (srcParent.parent && srcParent.name) {
    delete srcParent.parent.children[srcParent.name];
  }

  return { ok: true };
}

export function copyNode(state: VFSState, srcAbs: string, destAbs: string): { ok: boolean; error?: string } {
  const srcNode = getNode(state, srcAbs);
  if (!srcNode) return { ok: false, error: `cannot stat '${srcAbs}': No such file or directory` };

  // Deep clone
  const clone = JSON.parse(JSON.stringify(srcNode)) as VNode;

  const destNode = getNode(state, destAbs);
  if (destNode && destNode.type === 'dir') {
    const srcName = srcAbs.split('/').filter(Boolean).pop() || '';
    destNode.children[srcName] = clone;
  } else {
    const { parent, name } = getParentAndName(state, destAbs);
    if (!parent || !name) return { ok: false, error: 'invalid destination' };
    parent.children[name] = clone;
  }

  return { ok: true };
}

/**
 * Simple permission check. Returns true if the current user can perform the action.
 * For our simulator we keep this lightweight but realistic enough for teaching.
 */
export function hasPermission(state: VFSState, absPath: string, mode: 'read' | 'write' | 'execute'): boolean {
  const node = getNode(state, absPath);
  if (!node) return false;
  if (state.user === 'root') return true; // root can do everything

  const perms = node.perms;
  // perms format: -rwxrwxrwx (positions: 0=type, 1-3=owner, 4-6=group, 7-9=other)
  const offset = node.owner === state.user ? 1 : 7; // simplified: owner or other
  const r = perms[offset] === 'r';
  const w = perms[offset + 1] === 'w';
  const x = perms[offset + 2] === 'x';

  if (mode === 'read') return r;
  if (mode === 'write') return w;
  if (mode === 'execute') return x;
  return false;
}
