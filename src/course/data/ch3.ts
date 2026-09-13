// src/course/data/ch3.ts — Chapter 3: Bash Scripting Fundamentals
import type { Chapter } from '../types';
import { ran, ranRe, outputHas, fileHas, fileExists } from '../checks';

export const ch3: Chapter = {
  id: 'ch3',
  number: 3,
  title: 'Bash Scripting I — Fundamentals',
  tagline: 'Stop typing, start automating',
  lessons: [
    {
      id: 'ch3-l1',
      title: 'Your First Script',
      minutes: 12,
      content: `## A script is a saved list of commands

Create a file, make it executable, run it:

\`\`\`bash
printf '#!/bin/bash\necho "Recon starting..."\necho "Done."\n' > recon.sh
cat recon.sh              # inspect what you wrote
chmod 755 recon.sh        # make it executable (rwxr-xr-x)
./recon.sh                # run it!
\`\`\`

## Anatomy

- \`#!/bin/bash\` — the **shebang**. Line 1, tells Linux which interpreter runs the file.
- \`chmod 755\` — scripts need the execute bit (\`x\`), remember Lesson 1.5.
- \`./recon.sh\` — run a script in the current directory with \`./\` in front (the shell does not search \`.\` for programs).

> Why printf with \\n? It writes real newlines into the file so each command lands on its own line — the honest way to build small scripts from the terminal. On a desktop you would use a text editor.

## Scripts are just automation

Everything you can type, a script can run: 3 commands or 300. Attackers write scripts to automate recon; defenders write scripts to automate checks.`,
      practice: {
        prompt: 'Create an executable script ~/tools/hello.sh that prints Hello ShellStrike, then run it.',
        hints: [
          'Build it: printf \'#!/bin/bash\necho "Hello ShellStrike"\n\' > ~/tools/hello.sh',
          'Then: chmod 755 ~/tools/hello.sh and finally ~/tools/hello.sh (or ./tools/hello.sh from ~).',
        ],
        check: ctx => fileHas('~/tools/hello.sh', '#!/bin/bash')(ctx)
          && ranRe(/hello\.sh/)(ctx)
          && outputHas('Hello ShellStrike')(ctx),
      },
      quiz: [
        { q: 'What is the shebang line?', options: ['A comment about the author', '#!/bin/bash — it names the interpreter', 'A bash error', 'The script name'], answer: 1, explanation: 'The shebang on line 1 tells the kernel to run the file with bash.' },
        { q: 'Why does a script need chmod 755?', options: ['To encrypt it', 'To set the execute permission', 'To change its owner', '755 is not valid'], answer: 1, explanation: 'Without the x bit, Linux refuses to run the file.' },
        { q: 'How do you run a script in the current directory?', options: ['script.sh', './script.sh', 'run script.sh', 'bash < script.sh'], answer: 1, explanation: './ means "here in this directory".' },
      ],
    },
    {
      id: 'ch3-l2',
      title: 'Variables & Quoting',
      minutes: 14,
      content: `## Boxes with names

\`\`\`bash
TARGET="10.10.10.5"        # assign (NO spaces around =)
echo $TARGET               # use with $
echo "Scanning $TARGET"    # expands inside double quotes
\`\`\`

Rules that trip everyone:

- Assignment: \`NAME=value\` — **no spaces** around the equal sign
- Use: \`$NAME\` or \`$\{NAME}\`
- \`$USER\`, \`$HOME\`, \`$PWD\` are variables the shell already sets for you

## Quoting changes everything

\`\`\`bash
echo "Hello $USER"      # double quotes: variables EXPAND
echo 'Hello $USER'      # single quotes: taken literally
\`\`\`

\`printf '%s\\n' "$x"\` — quoting a variable when you use it is the professional habit: it keeps values with spaces in one piece.

## read — ask the user

\`\`\`bash
read -p "Enter target IP: " TARGET
\`\`\`

(In a script this pauses and stores what the user types.)

## Try it live

\`\`\`bash
TARGET=web01.corp.local
echo "Target is $TARGET"
echo 'Target is $TARGET'
\`\`\`

See the difference? That single-vs-double quote behaviour decides whether your payload works or leaks.`,
      practice: {
        prompt: 'Create and run ~/tools/var.sh containing a TARGET variable set to 10.10.10.5 and a line that echoes "Scanning $TARGET". Its output must contain: Scanning 10.10.10.5',
        hints: [
          'printf \'#!/bin/bash\nTARGET="10.10.10.5"\necho "Scanning $TARGET"\n\' > ~/tools/var.sh',
          'Then chmod 755 ~/tools/var.sh && ~/tools/var.sh',
        ],
        check: ctx => fileHas('~/tools/var.sh', 'TARGET=')(ctx) && outputHas('Scanning 10.10.10.5')(ctx),
      },
      quiz: [
        { q: 'Which assignment is correct bash?', options: ['TARGET = "10.10.10.5"', 'TARGET="10.10.10.5"', 'set TARGET 10.10.10.5', 'var TARGET="10.10.10.5"'], answer: 1, explanation: 'No spaces around the = in bash assignments.' },
        { q: 'What does echo \'$USER\' (single quotes) print?', options: ['hacker', 'The literal text $USER', 'An error', 'Nothing'], answer: 1, explanation: 'Single quotes prevent variable expansion.' },
        { q: 'What does $HOME usually hold?', options: ['The hostname', 'The current user\'s home directory', 'The root password', 'The last command'], answer: 1, explanation: 'e.g. /home/hacker — or /root for root.' },
        { q: 'How do you use a variable\'s value?', options: ['NAME', '$NAME', '@NAME', '&NAME'], answer: 1, explanation: 'The $ prefix reads the value.' },
      ],
    },
    {
      id: 'ch3-l3',
      title: 'Arguments & Exit Codes',
      minutes: 12,
      content: `## Scripts take arguments

\`\`\`bash
printf '#!/bin/bash\necho "Hello $1, you gave me $# args"\n' > greet.sh
chmod 755 greet.sh
./greet.sh Alice       # → Hello Alice, you gave me 1 args
\`\`\`

- \`$1, $2, ...\` — the 1st, 2nd... argument
- \`$#\` — how many arguments
- \`$0\` — the script's own name
- \`$@\` — all arguments

This is how every tool you know works: \`nmap 10.10.10.5\` just passed \`10.10.10.5\` as \`$1\` to the nmap program.

## Exit codes — how scripts talk

Every command exits with a number: **0 = success**, anything else = failure.

\`\`\`bash
ls /etc/passwd      # works
echo $?             # 0
ls /nope            # fails
echo $?             # 2
\`\`\`

\`$?\` holds the exit code of the last command. Scripts end with \`exit 0\` or \`exit 1\` so that OTHER scripts (and cron jobs, and pipelines) can react to their success.`,
      practice: {
        prompt: 'Create ~/tools/greet.sh that echoes "Hello $1" and run it with your name (any argument). Output must start with Hello.',
        hints: [
          'printf \'#!/bin/bash\necho "Hello $1"\n\' > ~/tools/greet.sh',
          'chmod 755 ~/tools/greet.sh && ~/tools/greet.sh Alice',
        ],
        check: ctx => fileHas('~/tools/greet.sh', 'echo "Hello $1"')(ctx) && outputHas('Hello ')(ctx),
      },
      quiz: [
        { q: 'Inside a script, what is $1?', options: ['The script name', 'The first argument passed to it', 'Exit code 1', 'The PID'], answer: 1, explanation: '$1, $2... are positional arguments; $0 is the script name.' },
        { q: 'What does $# hold?', options: ['The number 1', 'The count of arguments', 'The exit code', 'The line count'], answer: 1, explanation: '$# = number of arguments passed.' },
        { q: 'What exit code means success?', options: ['1', '-1', '0', 'Any code'], answer: 2, explanation: '0 is success; non-zero signals failure.' },
        { q: 'What does echo $? print right after a failed command?', options: ['0', '1', 'Nothing', 'A non-zero code such as 2'], answer: 3, explanation: 'The failing command\'s specific non-zero code (often 1 or 2).' },
      ],
    },
    {
      id: 'ch3-l4',
      title: 'Command Substitution',
      minutes: 10,
      content: `## Use a command's output as a value

\`\`\`bash
NOW=$(date)                     # capture output of date into NOW
echo "Scan started at $NOW"
USERLIST=$(cat /etc/passwd | wc -l)
echo "This box has $USERLIST accounts"
\`\`\`

\`$(command)\` runs the command first, then substitutes its **output** into your line. Backticks \` \`command\` \` do the same thing, but \`$()\` nests cleanly — use \`$()\`.

## Read files into loops (a preview)

\`\`\`bash
for ip in $(cat targets.txt); do echo "Pinging $ip"; done
\`\`\`

That pattern — "for each line of my target file, do something" — is the beating heart of every batch scanner ever written. You will build one in the next lab.

## In scripts vs the command line

The terminal here expands \`$USER\` and friends directly, while \`$(...)\` substitution runs inside scripts. Both are the same bash behaviour.

> An attacker who captures $(cat /etc/passwd) into a variable has just exfiltrated a user list in one line.`,
      practice: {
        prompt: 'Create ~/tools/count.sh that stores the number of lines of /etc/passwd in a variable (using $(cat /etc/passwd | wc -l)) and echoes "Accounts: <n>". Run it.',
        hints: [
          'printf \'#!/bin/bash\nN=$(cat /etc/passwd | wc -l)\necho "Accounts: $N"\n\' > ~/tools/count.sh',
          'chmod 755 ~/tools/count.sh && ~/tools/count.sh',
        ],
        check: ctx => fileHas('~/tools/count.sh', '$(cat /etc/passwd')(ctx) && outputHas('Accounts: 5')(ctx),
      },
      quiz: [
        { q: 'What does $(date) do inside a script?', options: ['Prints the literal text $(date)', 'Runs date and substitutes its output', 'Starts a background date', 'Nothing'], answer: 1, explanation: 'Command substitution: execute, then insert the output.' },
        { q: 'How do you feed a file of IPs into a for loop?', options: ['for ip in targets.txt', 'for ip in $(cat targets.txt)', 'loop targets.txt', 'read targets.txt'], answer: 1, explanation: '$(cat file) expands to the file contents, which the loop iterates.' },
        { q: 'Which is the modern nesting-safe substitution syntax?', options: ['`cmd`', '$(cmd)', '${cmd}', '@cmd@'], answer: 1, explanation: '$(...) nests cleanly; backticks are legacy.' },
      ],
    },
  ],
  lab: {
    id: 'ch3-lab',
    title: 'Lab 3 — The Recon Script',
    brief: 'Build your first real tool: a reusable recon script that takes an IP as an argument and scans it. This is exactly how pentesters turn 20 manual commands into one.',
    steps: [
      { goal: 'Create ~/tools/ips.txt containing two lines: 10.10.10.5 and 10.10.10.20.', hint: 'printf \'10.10.10.5\n10.10.10.20\n\' > ~/tools/ips.txt', check: ctx => fileHas('~/tools/ips.txt', '10.10.10.5')(ctx) && fileHas('~/tools/ips.txt', '10.10.10.20')(ctx) },
      { goal: 'Create ~/tools/scanme.sh with a shebang, an echo of "Target: $1" and an nmap $1 line.', hint: 'printf \'#!/bin/bash\necho "Target: $1"\nnmap $1\n\' > ~/tools/scanme.sh', check: ctx => fileHas('~/tools/scanme.sh', '#!/bin/bash')(ctx) && fileHas('~/tools/scanme.sh', 'nmap $1')(ctx) },
      { goal: 'Make ~/tools/scanme.sh executable.', hint: 'chmod 755 ~/tools/scanme.sh', check: ctx => ranRe(/chmod\s+(755|\+x).*scanme\.sh/)(ctx) },
      { goal: 'Run it against the first target: ~/tools/scanme.sh 10.10.10.5 — the output must show both "Target: 10.10.10.5" and nmap results.', hint: 'Exactly: ~/tools/scanme.sh 10.10.10.5', check: ctx => outputHas('Target: 10.10.10.5')(ctx) && outputHas('Starting Nmap')(ctx) },
      { goal: 'Write ~/tools/sweep.sh that loops over every IP in ips.txt (for ip in $(cat ~/tools/ips.txt)) and echoes "Pinging $ip".', hint: 'printf \'#!/bin/bash\nfor ip in $(cat ~/tools/ips.txt); do\n  echo "Pinging $ip"\ndone\n\' > ~/tools/sweep.sh', check: ctx => fileHas('~/tools/sweep.sh', 'for ip in $(cat')(ctx) },
      { goal: 'Make sweep.sh executable and run it — you should see "Pinging 10.10.10.5" AND "Pinging 10.10.10.20".', hint: 'chmod 755 ~/tools/sweep.sh && ~/tools/sweep.sh', check: ctx => outputHas('Pinging 10.10.10.5')(ctx) && outputHas('Pinging 10.10.10.20')(ctx) },
    ],
  },
  cheat: [
    { cmd: 'printf "line\\n" > f.sh', desc: 'write lines into a file' },
    { cmd: 'chmod 755 script.sh', desc: 'make a script executable' },
    { cmd: './script.sh args', desc: 'run a local script with arguments' },
    { cmd: '#!/bin/bash', desc: 'shebang — run with bash' },
    { cmd: 'NAME=value', desc: 'assign variable (no spaces!)' },
    { cmd: '$NAME / $\{NAME}', desc: 'use a variable' },
    { cmd: '"$x" vs \'$x\'', desc: 'double = expand, single = literal' },
    { cmd: 'read -p "Msg" VAR', desc: 'ask the user for input' },
    { cmd: '$1 $2 $# $@', desc: 'arguments: 1st, 2nd, count, all' },
    { cmd: 'echo $?', desc: 'exit code of last command' },
    { cmd: 'X=$(command)', desc: 'store command output in a variable' },
  ],
};
