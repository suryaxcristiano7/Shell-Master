// src/App.tsx

import React from 'react';
import { Terminal } from './components/Terminal';

function App() {
  return (
    <div className="min-h-screen bg-ink-900 text-slate-200 flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-700 bg-ink-800 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-neon-green to-neon-cyan rounded-lg flex items-center justify-center">
              <span className="text-ink-900 font-bold text-xl">S</span>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">ShellStrike Academy</h1>
              <p className="text-xs text-slate-400">Shell Scripting for Ethical Hackers</p>
            </div>
          </div>
          
          <nav className="flex items-center gap-6">
            <a href="#" className="text-sm text-slate-300 hover:text-neon-cyan transition-colors">
              Modules
            </a>
            <a href="#" className="text-sm text-slate-300 hover:text-neon-cyan transition-colors">
              Cheat Sheet
            </a>
            <a href="#" className="text-sm text-slate-300 hover:text-neon-cyan transition-colors">
              Progress
            </a>
            <button className="px-4 py-2 bg-neon-green text-ink-900 rounded-lg font-semibold hover:bg-neon-cyan transition-colors">
              Start Learning
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex flex-col">
        {/* Terminal Section */}
        <div className="flex-1 p-6">
          <div className="max-w-7xl mx-auto h-full flex flex-col gap-4">
            {/* Info Bar */}
            <div className="bg-ink-800 border border-slate-700 rounded-lg px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse"></div>
                  <span className="text-sm text-slate-300">Terminal Active</span>
                </div>
                <div className="text-xs text-slate-500">
                  <span className="text-slate-400">User:</span> hacker@shellstrike
                </div>
                <div className="text-xs text-slate-500">
                  <span className="text-slate-400">Session:</span> pts/0
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 rounded transition-colors">
                  Reset
                </button>
                <button className="px-3 py-1 text-xs bg-neon-cyan text-ink-900 hover:bg-neon-green rounded transition-colors font-semibold">
                  Fullscreen
                </button>
              </div>
            </div>

            {/* Terminal */}
            <Terminal className="flex-1" />

            {/* Quick Commands */}
            <div className="bg-ink-800 border border-slate-700 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Quick Start Commands</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {[
                  { cmd: 'whoami', desc: 'Current user' },
                  { cmd: 'ls -la', desc: 'List files' },
                  { cmd: 'cat /etc/passwd', desc: 'View users' },
                  { cmd: 'nmap 10.10.10.5', desc: 'Scan target' },
                  { cmd: 'hydra -l admin -P pass ssh://10.10.10.5', desc: 'Brute force' },
                  { cmd: 'gobuster -u http://10.10.10.5 -w wordlist.txt', desc: 'Dir busting' },
                  { cmd: 'curl http://10.10.10.5', desc: 'Fetch page' },
                  { cmd: 'help', desc: 'All commands' },
                ].map((item, i) => (
                  <button
                    key={i}
                    className="text-left px-3 py-2 bg-ink-700 hover:bg-ink-600 rounded border border-slate-600 transition-colors group"
                  >
                    <div className="font-mono text-xs text-neon-green group-hover:text-neon-cyan">
                      {item.cmd}
                    </div>
                    <div className="text-xs text-slate-400 mt-1">{item.desc}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-ink-800 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between text-xs text-slate-500">
          <div>
            © 2026 ShellStrike Academy. For educational purposes only.
          </div>
          <div className="flex items-center gap-4">
            <span>Version 1.0.0</span>
            <span className="text-neon-green">● Online</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
