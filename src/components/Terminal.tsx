// src/components/Terminal.tsx

import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { createShellState, executeCommand, ShellState } from '../lib/shell';

interface TerminalProps {
  className?: string;
}

export const Terminal: React.FC<TerminalProps> = ({ className }) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [shell] = useState<ShellState>(() => createShellState());
  const xtermRef = useRef<XTerm | null>(null);
  
  // Buffer for current input line
  const inputBuffer = useRef<string>('');
  const cursorPos = useRef<number>(0);

  useEffect(() => {
    if (!terminalRef.current) return;

    // Initialize xterm
    const term = new XTerm({
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize: 14,
      theme: {
        background: '#0b0f16', // Dark ink color
        foreground: '#e2e8f0', // Slate-200
        cursor: '#39ff88',     // Neon Green
        selectionBackground: '#22d3ee44',
        black: '#000000',
        red: '#ff5555',
        green: '#39ff88',
        yellow: '#fbbf24',
        blue: '#22d3ee',
        magenta: '#ff3d9a',
        cyan: '#22d3ee',
        white: '#ffffff',
        brightBlack: '#7f8c98',
        brightRed: '#ff6e6e',
        brightGreen: '#5fff9e',
        brightYellow: '#ffd54f',
        brightBlue: '#4fc3f7',
        brightMagenta: '#ff70a6',
        brightCyan: '#4fc3f7',
        brightWhite: '#ffffff',
      },
      scrollback: 1000,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;

    // Initial Welcome Message
    const welcome = `
\x1b[1;32m┌──(hacker㉿shellstrike)-[~]\n└─\x1b[1;34m$ \x1b[0mWelcome to ShellStrike Academy Terminal Emulator v1.0
\x1b[0mType 'help' to see available commands.
Type 'exit' to close session (simulated).

`;
    term.write(welcome);
    writePrompt(term, shell);

    // Handle Input
    let buffer = '';
    
    term.onData((data) => {
      switch (data) {
        case '\r': // Enter
          term.write('\r\n');
          handleCommand(buffer, term, shell);
          buffer = '';
          break;
        
        case '\u007F': // Backspace
          if (buffer.length > 0) {
            buffer = buffer.slice(0, -1);
            term.write('\b \b');
          }
          break;
        
        case '\u0003': // Ctrl+C
          buffer = '';
          term.write('^C\r\n');
          writePrompt(term, shell);
          break;
          
        case '\u0004': // Ctrl+D
          buffer = '';
          term.write('logout\r\n');
          term.write('\x1b[2J\x1b[H'); // Clear screen
          writePrompt(term, shell);
          break;

        default:
          // Printable characters
          if (data >= String.fromCharCode(0x20) && data <= String.fromCharCode(0x7E)) {
            buffer += data;
            term.write(data);
          }
      }
    });

    // Handle Resize
    const handleResize = () => fitAddon.fit();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      term.dispose();
    };
  }, []);

  return (
    <div 
      ref={terminalRef} 
      className={`w-full h-full rounded-lg overflow-hidden border border-slate-700 shadow-2xl ${className}`}
      style={{ minHeight: '400px' }}
    />
  );
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getPrompt(state: ShellState): string {
  const cwd = state.vfs.cwd.replace(state.vfs.home, '~');
  // ANSI Color Codes for Kali Prompt
  // Green: \x1b[1;32m
  // Blue: \x1b[1;34m
  // Reset: \x1b[0m
  return `\x1b[1;32m┌──(\x1b[1;34m${state.vfs.user}㉿shellstrike\x1b[1;32m)-[\x1b[0m${cwd}\x1b[1;32m]\n└─\x1b[1;34m$\x1b[0m `;
}

function writePrompt(term: XTerm, state: ShellState) {
  term.write(getPrompt(state));
}

async function handleCommand(input: string, term: XTerm, state: ShellState) {
  if (!input.trim()) {
    writePrompt(term, state);
    return;
  }

  // Show loading indicator for "heavy" commands (simulated delay)
  const heavyCommands = ['nmap', 'hydra', 'gobuster', 'sqlmap', 'find'];
  const cmdName = input.trim().split(' ')[0];
  
  if (heavyCommands.includes(cmdName)) {
    term.write('\r\n\x1b[33m[*] Processing...\x1b[0m');
    await new Promise(r => setTimeout(r, 800)); // Fake delay
    term.write('\r\x1b[2K'); // Clear loading line
  }

  const result = await executeCommand(input, state);
  
  if (result.output) {
    term.write(result.output);
  }
  
  // Check if command changed user (sudo bash)
  if (input.trim() === 'sudo bash') {
    // Prompt is already updated in state by cmdSudo
  }

  writePrompt(term, state);
}
