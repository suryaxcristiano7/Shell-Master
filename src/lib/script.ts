// src/lib/script.ts
// A small educational bash interpreter for the ShellStrike Academy emulator.
// Supports: if/elif/else/fi, for-in, while, case/esac, functions,
// positional parameters, environment variables, $() command substitution,
// $(( )) arithmetic, and every command the simulator implements.

import { executeCommand, ShellState, CommandResult } from './shell';
import { getNode, readFile, resolvePath, writeFile } from './vfs';

// ─── AST ─────────────────────────────────────────────────────────────────────

type Node =
  | { type: 'cmd'; line: string }
  | { type: 'if'; branches: { cond: string | null; body: Node[] }[] }
  | { type: 'for'; variable: string; items: string; body: Node[] }
  | { type: 'while'; cond: string; body: Node[] }
  | { type: 'case'; subject: string; branches: { pattern: string; body: Node[] }[] }
  | { type: 'func'; name: string; body: Node[] };

interface Frame {
  kind: 'if' | 'for' | 'while' | 'case' | 'caseBranch' | 'func';
  node: Node;
  target: Node[];
}

// ─── Parser ─────────────────────────────────────────────────────────────────

function parseScript(content: string): Node[] {
  const root: Node[] = [];
  const stack: Frame[] = [];
  let current = root;

  const push = (frame: Frame) => { stack.push(frame); current = frame.target; };
  const closeFrame = () => {
    const f = stack.pop();
    if (!f) return;
    // Attach completed node to its parent body
    stack.length > 0
      ? (stack[stack.length - 1].target.push(f.node))
      : root.push(f.node);
    current = stack.length > 0 ? stack[stack.length - 1].target : root;
  };

  const lines = content.split('\n');
  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    // Normalise "if [ ... ]; then" → "if [ ... ]" (capture 'then' on same line)
    const thenDo = line.match(/;\s*(then|do)\s*$/);
    if (thenDo) line = line.slice(0, thenDo.index).trim();
    // "else" on the same line as code: keep simple — only handle bare forms

    // ── keywords ──
    if (line === 'then' || line === 'do' || line === 'in') continue; // structural no-ops

    // Closers carrying a block redirect:  done > file   fi >> file   esac > file
    const closerRedirect = line.match(/^(fi|done|esac)\s*(>>?)\s*(\S+)\s*$/);
    if (closerRedirect) {
      const top = stack[stack.length - 1];
      if (top) {
        (top.node as Node & { redirect?: { file: string; append: boolean } }).redirect =
          { file: closerRedirect[3], append: closerRedirect[2] === '>>' };
      }
      line = closerRedirect[1];
    }

    if (line === '}' || line === 'fi' || line === 'done' || line === 'esac' || line === ';;') {
      // A ';;' closes the current case branch body
      if (line === ';;' && stack.length > 0 && stack[stack.length - 1].kind === 'caseBranch') {
        closeFrame();
        continue;
      }
      if (line !== ';;') closeFrame();
      continue;
    }

    if (line === 'else' || line === 'elif *') {
      const top = stack[stack.length - 1];
      if (top && top.kind === 'if') {
        const ifNode = top.node as Extract<Node, { type: 'if' }>;
        const newBody: Node[] = [];
        ifNode.branches.push({ cond: null, body: newBody });
        top.target = newBody;
        current = newBody;
      }
      continue;
    }

    const elifMatch = line.match(/^elif\s+(.+)$/);
    if (elifMatch) {
      const top = stack[stack.length - 1];
      if (top && top.kind === 'if') {
        const ifNode = top.node as Extract<Node, { type: 'if' }>;
        const newBody: Node[] = [];
        ifNode.branches.push({ cond: elifMatch[1].trim(), body: newBody });
        top.target = newBody;
        current = newBody;
      }
      continue;
    }

    const ifMatch = line.match(/^if\s+(.+)$/);
    if (ifMatch) {
      const body: Node[] = [];
      const node: Node = { type: 'if', branches: [{ cond: ifMatch[1].trim(), body }] };
      push({ kind: 'if', node, target: body });
      continue;
    }

    const forMatch = line.match(/^for\s+([A-Za-z_]\w*)\s+in\s+(.+)$/);
    if (forMatch) {
      const body: Node[] = [];
      const node: Node = { type: 'for', variable: forMatch[1], items: forMatch[2].replace(/;\s*$/, ''), body };
      push({ kind: 'for', node, target: body });
      continue;
    }

    const whileMatch = line.match(/^while\s+(.+)$/);
    if (whileMatch) {
      const body: Node[] = [];
      const node: Node = { type: 'while', cond: whileMatch[1].trim(), body };
      push({ kind: 'while', node, target: body });
      continue;
    }

    const caseMatch = line.match(/^case\s+(.+)\s+in$/);
    if (caseMatch) {
      const node: Node = { type: 'case', subject: caseMatch[1].trim(), branches: [] };
      push({ kind: 'case', node, target: [] });
      continue;
    }

    // inside a case: a pattern line like  start) cmd ;;  or  *) or  start)
    if (stack.length > 0 && stack[stack.length - 1].kind === 'case') {
      const patMatch = line.match(/^(.+?)\)\s*(.*)$/);
      if (patMatch) {
        const caseNode = stack[stack.length - 1].node as Extract<Node, { type: 'case' }>;
        const body: Node[] = [];
        caseNode.branches.push({ pattern: patMatch[1].trim(), body });
        const frame: Frame = { kind: 'caseBranch', node: { type: 'cmd', line: '' }, target: body };
        push(frame);
        (frame as Frame & { dummy?: boolean }).dummy = true;
        // Handle everything after the pattern on the same line
        const rest = patMatch[2].trim();
        if (rest) {
          if (rest === ';;' || rest.endsWith(' ;;')) {
            const cmd = rest.replace(/;;\s*$/, '').trim();
            if (cmd) current.push({ type: 'cmd', line: cmd });
            closeFrame(); // ';;' was on this line
          } else {
            current.push({ type: 'cmd', line: rest });
          }
        }
        continue;
      }
    }

    const funcMatch = line.match(/^([A-Za-z_]\w*)\s*\(\)\s*\{?$/);
    if (funcMatch) {
      const body: Node[] = [];
      const node: Node = { type: 'func', name: funcMatch[1], body };
      push({ kind: 'func', node, target: body });
      continue;
    }

    current.push({ type: 'cmd', line });
  }

  return root;
}

// ─── Substitution ────────────────────────────────────────────────────────────

function safeArithmetic(expr: string, state: ShellState, args: string[]): string {
  // Expand both $VAR and bare identifiers (bash allows i+1 without the $)
  const expanded = expr.replace(/\$?([A-Za-z_]\w*)/g, (whole, v) =>
    state.env[v] !== undefined ? String(state.env[v]) : whole);
  if (!/^[\d\s+\-*/%().]*$/.test(expanded)) return expanded;
  try {
    // eslint-disable-next-line no-new-func
    const val = Function(`"use strict"; return (${expanded});`)();
    return String(val);
  } catch {
    return expanded;
  }
}

async function substitute(line: string, state: ShellState, args: string[]): Promise<string> {
  let out = line;

  // $(( arithmetic ))
  out = out.replace(/\$\(\((.+?)\)\)/g, (_, expr) => safeArithmetic(expr, state, args));

  // $(seq a b) and $(seq a b step)
  out = out.replace(/\$\(seq\s+(-?\d+)\s+(-?\d+)(?:\s+(-?\d+))?\)/g, (_, a, b, s) => {
    const start = parseInt(a), end = parseInt(b), step = s ? parseInt(s) : 1;
    const nums: string[] = [];
    for (let i = start; step > 0 ? i <= end : i >= end; i += step) nums.push(String(i));
    return nums.join(' ');
  });

  // $(command) — generic command substitution
  for (let guard = 0; guard < 10; guard++) {
    const m = out.match(/\$\(([^()]+)\)/);
    if (!m) break;
    const r = await executeCommand(m[1], state);
    out = out.replace(m[0], r.output.trim().replace(/\n$/, ''));
  }

  // Exit code of the last command
  out = out.replace(/\$\?/g, String(state.exitCode));

  // Positional parameters: $1..$9, $#, $@
  out = out.replace(/\$(\d)/g, (_, d) => args[parseInt(d) - 1] ?? '');
  out = out.replace(/\$#/g, String(args.length));
  out = out.replace(/\$@/g, args.join(' ');

  // Named variables: ${VAR} and $VAR
  out = out.replace(/\$\{(\w+)\}/g, (_, v) => varValue(v, state));
  out = out.replace(/\$(\w+)/g, (_, v) => varValue(v, state));

  return out;
}

function varValue(v: string, state: ShellState): string {
  if (v === 'PWD') return state.vfs.cwd;
  if (v === 'HOME') return state.vfs.home;
  if (v === 'USER') return state.vfs.user;
  return state.env[v] ?? '';
}

// ─── Condition evaluation ────────────────────────────────────────────────────

function evalTest(cond: string, state: ShellState): boolean {
  let c = cond.trim();
  let negate = false;
  while (c.startsWith('!')) { negate = !negate; c = c.slice(1).trim(); }

  // Strip brackets
  c = c.replace(/^\[\[?\s*/, '').replace(/\s*\]\]?$/, '').trim();
  if (!c) return negate;

  const parts = c.match(/"[^"]*"|'[^']*'|\S+/g)?.map(p => p.replace(/^["']|["']$/g, '')) ?? [];

  // Unary file/string tests
  if (parts.length === 2 && parts[0].startsWith('-')) {
    const val = parts[1];
    let res = false;
    const path = val.startsWith('/') || val.startsWith('~') ? resolvePath(state.vfs.cwd, val, state.vfs.home) : resolvePath(state.vfs.cwd, val, state.vfs.home);
    const node = getNode(state.vfs, path);
    switch (parts[0]) {
      case '-f': res = !!node && node.type === 'file'; break;
      case '-d': res = !!node && node.type === 'dir'; break;
      case '-e': res = !!node; break;
      case '-x': res = !!node && node.perms.includes('x'); break;
      case '-r': res = !!node; break;
      case '-w': res = !!node; break;
      case '-z': res = val === ''; break;
      case '-n': res = val !== ''; break;
    }
    return negate ? !res : res;
  }

  // Binary tests
  if (parts.length === 3) {
    const [a, op, b] = parts;
    let res = false;
    switch (op) {
      case '=': case '==': res = a === b; break;
      case '!=': res = a !== b; break;
      case '-eq': res = parseInt(a) === parseInt(b); break;
      case '-ne': res = parseInt(a) !== parseInt(b); break;
      case '-lt': res = parseInt(a) < parseInt(b); break;
      case '-le': res = parseInt(a) <= parseInt(b); break;
      case '-gt': res = parseInt(a) > parseInt(b); break;
      case '-ge': res = parseInt(a) >= parseInt(b); break;
    }
    return negate ? !res : res;
  }

  // 'true' / 'false'
  if (c === 'true') return !negate;
  if (c === 'false') return negate;

  return false;
}

// ─── Execution ───────────────────────────────────────────────────────────────

interface RunCtx {
  args: string[];
  funcs: Record<string, Node>;
  aborted: boolean;
  output: string;
}

async function execBlock(body: Node[], state: ShellState, ctx: RunCtx): Promise<void> {
  for (const node of body) {
    if (ctx.aborted) return;
    const rd = (node as Node & { redirect?: { file: string; append: boolean } }).redirect;
    if (rd) {
      // Block redirect: capture this node's output and write it to the file
      const subCtx: RunCtx = { args: ctx.args, funcs: ctx.funcs, aborted: false, output: '' };
      await execNode(node, state, subCtx);
      ctx.aborted = ctx.aborted || subCtx.aborted;
      let file = rd.file;
      if (file === '~' || file.startsWith('~/')) file = state.vfs.home + file.slice(1);
      const abs = file.startsWith('/') ? file : resolvePath(state.vfs.cwd, file, state.vfs.home);
      const existing = readFile(state.vfs, abs);
      writeFile(state.vfs, abs, (rd.append && existing !== null ? existing : '') + subCtx.output);
    } else {
      await execNode(node, state, ctx);
    }
  }
}

async function execNode(node: Node, state: ShellState, ctx: RunCtx): Promise<void> {
  switch (node.type) {
    case 'cmd': {
      let line = await substitute(node.line, state, ctx.args);

      // 'local' keyword inside functions behaves like an assignment
      line = line.replace(/^local\s+/, '');

      if (!line.trim()) return;

      // exit stops the script
      if (line.trim() === 'exit' || line.trim().startsWith('exit ')) { ctx.aborted = true; return; }

      // Function call? (share the ctx so output accumulates — only args swap)
      const name = line.trim().split(/\s+/)[0];
      const funcNode = ctx.funcs[name];
      if (funcNode && funcNode.type === 'func') {
        const callArgs = line.trim().split(/\s+/).slice(1);
        const prevArgs = ctx.args;
        ctx.args = callArgs;
        await execBlock(funcNode.body, state, ctx);
        ctx.args = prevArgs;
        return;
      }

      const res = await executeCommand(line, state);
      ctx.output += res.output;
      return;
    }

    case 'if': {
      for (const branch of node.branches) {
        if (branch.cond === null) {
          await execBlock(branch.body, state, ctx);
          return;
        }
        const ok = await evalCond(branch.cond, state, ctx.args);
        if (ok) {
          await execBlock(branch.body, state, ctx);
          return;
        }
      }
      return;
    }

    case 'for': {
      const itemsRaw = await substitute(node.items, state, ctx.args);
      const items = itemsRaw.split(/\s+/).filter(Boolean);
      const prev = state.env[node.variable];
      for (const item of items) {
        state.env[node.variable] = item;
        await execBlock(node.body, state, ctx);
        if (ctx.aborted) break;
      }
      if (prev === undefined) delete state.env[node.variable]; else state.env[node.variable] = prev;
      return;
    }

    case 'while': {
      let guard = 0;
      while (guard++ < 500) {
        if (ctx.aborted) break;
        const ok = await evalCond(node.cond, state, ctx.args);
        if (!ok) break;
        await execBlock(node.body, state, ctx);
      }
      return;
    }

    case 'case': {
      const subject = (await substitute(node.subject, state, ctx.args)).trim();
      for (const branch of node.branches) {
        const pat = branch.pattern.replace(/^["']|["']$/g, '');
        const hit = pat === '*' || pat === subject || (pat.endsWith('*') && subject.startsWith(pat.slice(0, -1)));
        if (hit) {
          await execBlock(branch.body, state, ctx);
          return;
        }
      }
      return;
    }

    case 'func': {
      ctx.funcs[node.name] = node;
      return;
    }
  }
}

async function evalCond(cond: string, state: ShellState, args: string[] = []): Promise<boolean> {
  // Substitute variables ($i, $VAR) first
  const c = (await substitute(cond, state, args)).trim();
  // Bracket tests
  if (c.startsWith('[')) return evalTest(c, state);
  if (c === 'true') return true;
  if (c === 'false') return false;
  // Otherwise: run the command and check its exit code
  const res = await executeCommand(c, state);
  return res.exitCode === 0;
}

// ─── Entry point ─────────────────────────────────────────────────────────────

export async function runBashScript(content: string, args: string[], state: ShellState): Promise<CommandResult> {
  const body = parseScript(content);
  const ctx: RunCtx = { args, funcs: {}, aborted: false, output: '' };
  await execBlock(body, state, ctx);
  return { output: ctx.output, exitCode: 0 };
}
