// src/course/data/ch2.ts — Chapter 2: Text Processing & Pipes
import type { Chapter } from '../types';
import { ran, ranRe, outputHas, fileHas, fileExists } from '../checks';

export const ch2: Chapter = {
  id: 'ch2',
  number: 2,
  title: 'Text Processing & Pipes',
  tagline: 'The hacker superpower: slicing text at speed',
  lessons: [
    {
      id: 'ch2-l1',
      title: 'Redirection: > >> <',
      minutes: 10,
      content: `## Send output anywhere

Commands write to **stdout** (your screen). Redirection lets you send that output into files instead:

\`\`\`bash
echo "10.10.10.5" > targets.txt       # write (REPLACES the file)
echo "10.10.10.20" >> targets.txt      # append (adds a line)
cat targets.txt
\`\`\`

- \`>\` — create/overwrite
- \`>>\` — create/append
- \`<\` — feed a file INTO a command's input

\`\`\`bash
grep "Failed" < /var/log/auth.log     # read input from a file
\`\`\`

## Why attackers love this

Evidence collection. You will scan a target, save the output, and grep it later:

\`\`\`bash
nmap -sV 10.10.10.5 > scan.txt     # save a scan for the report
cat scan.txt
\`\`\`

> In a real engagement, every command you run goes into a dated log file. Redirection is how you build that trail.`,
      practice: {
        prompt: 'Build a target list: create targets.txt containing first 10.10.10.5 (with >), then append 10.10.10.20 (with >>).',
        hints: ['`echo "10.10.10.5" > targets.txt` then `echo "10.10.10.20" >> targets.txt`.', 'The quotes keep the line as one argument.'],
        check: ctx => fileHas('~/targets.txt', '10.10.10.5')(ctx) && fileHas('~/targets.txt', '10.10.10.20')(ctx),
      },
      quiz: [
        { q: 'What is the difference between > and >>?', options: ['None', '> overwrites, >> appends', '>> overwrites, > appends', '> only works on logs'], answer: 1, explanation: '> replaces the file content; >> adds to the end.' },
        { q: 'Which command saves a scan into scan.txt?', options: ['nmap 10.10.10.5 << scan.txt', 'nmap 10.10.10.5 > scan.txt', 'nmap 10.10.10.5 scan.txt', 'save nmap scan.txt'], answer: 1, explanation: 'Redirect stdout with > into the file.' },
        { q: 'What does echo "x" > existing.txt do to old content?', options: ['Keeps it', 'Appends after it', 'Destroys it', 'Backs it up'], answer: 2, explanation: '> truncates the file first — the old content is gone.' },
      ],
    },
    {
      id: 'ch2-l2',
      title: 'Pipes: |',
      minutes: 10,
      content: `## One command feeds the next

The **pipe** \`|\` takes the stdout of one command and makes it the stdin of the next:

\`\`\`bash
cat /var/log/auth.log | wc -l        # count lines in the log
\`\`\`

This is the core Unix idea: small sharp tools, combined in chains.

\`\`\`bash
ls -la /etc | wc -l                  # how many files in /etc?
cat /etc/passwd | head -n 3          # first 3 users
\`\`\`

## Think like a pipeline

\`cat file\` → \`grep pattern\` → \`count\` → screen.

Later this becomes a weapon:

\`\`\`bash
cat /var/log/auth.log | grep "Failed password"    # every failed login
\`\`\`

One pipe just turned 20 log lines into pure attacker intelligence — real logs have millions of lines and this still takes a second.`,
      chart: 'pipeflow',
      practice: {
        prompt: 'Count the lines of /var/log/auth.log using a pipe: send cat output into wc -l.',
        hints: ['`cat /var/log/auth.log | wc -l`', 'The pipe character is Shift+Backslash on most keyboards.'],
        check: ctx => ranRe(/^cat\s+\/var\/log\/auth\.log\s*\|\s*wc/)(ctx),
      },
      quiz: [
        { q: 'What does the pipe | do?', options: ['Runs two commands in parallel', 'Sends one command\'s output into the next command', 'Compares two files', 'Creates a backup'], answer: 1, explanation: 'stdout of the left command becomes stdin of the right command.' },
        { q: 'What does `cat auth.log | wc -l` print?', options: ['The file', 'The number of lines', 'The last line', 'The word "auth.log"'], answer: 1, explanation: 'wc -l counts the lines piped into it.' },
        { q: 'Why do hackers chain commands with pipes?', options: ['It looks impressive', 'To process large data quickly with small tools', 'Pipes encrypt output', 'To run as root'], answer: 1, explanation: 'Chains of small tools slice huge logs instantly.' },
      ],
    },
    {
      id: 'ch2-l3',
      title: 'grep — Find the Needle',
      minutes: 12,
      content: `## grep = global regex print

\`grep\` prints lines that **match a pattern**:

\`\`\`bash
grep "Failed password" /var/log/auth.log
grep root /etc/passwd
\`\`\`

## The flags that matter

\`\`\`bash
grep -i "failed" auth.log     # -i: case-insensitive
grep -c "Failed" auth.log     # -c: just COUNT matching lines
grep -n "root" /etc/passwd   # -n: show line numbers
grep -v "sshd" auth.log      # -v: INVERT — lines that DON'T match
\`\`\`

## Your first attacker analysis

Someone has been brute-forcing this machine. Find out:

\`\`\`bash
grep "Failed password" /var/log/auth.log       # see every attempt
grep -c "Failed password" /var/log/auth.log     # how many?
grep "Failed password for root" /var/log/auth.log   # are they after root?
\`\`\`

## Regex teaser

\`grep\` understands regular expressions:

\`\`\`bash
grep "Failed password for \(invalid user \)\?admin" auth.log   # optional text
grep "^Sep 13 03" auth.log     # lines starting with "Sep 13 03"
\`\`\`

> The regex rabbit hole is deep — anchors (^ start, $ end), classes ([0-9]), repetition (* + ?). You already know enough to hunt.`,
      practice: {
        prompt: 'Someone attacked this machine. Count how many "Failed password" events are in /var/log/auth.log (grep with the -c flag).',
        hints: ['`grep -c "Failed password" /var/log/auth.log`', 'Quote the pattern — it contains a space.'],
        check: ctx => ranRe(/^grep\s+-c\s+"Failed password"\s+\/var\/log\/auth\.log/)(ctx) && outputHas('13')(ctx),
      },
      quiz: [
        { q: 'What does `grep -c "x" file` output?', options: ['The matching lines', 'The number of matching lines', 'The file count', 'Line numbers'], answer: 1, explanation: '-c suppresses the line and prints only the count.' },
        { q: 'Which flag makes grep case-insensitive?', options: ['-v', '-i', '-n', '-a'], answer: 1, explanation: '-i = ignore case.' },
        { q: 'What does `grep -v sshd auth.log` show?', options: ['Only sshd lines', 'Lines that do NOT contain sshd', 'Verbose output', 'Version info'], answer: 1, explanation: '-v inverts the match.' },
        { q: 'In regex, what does ^ mean at the start of a pattern?', options: ['Exponent', 'Match start of line', 'Negation', 'Any character'], answer: 1, explanition: '^ anchors the pattern to the beginning of the line.' },
      ],
    },
    {
      id: 'ch2-l4',
      title: 'sort, uniq, cut, tr',
      minutes: 14,
      content: `## The finishing moves

\`\`\`bash
sort file            # sort lines alphabetically
sort -r file         # reverse
sort -n nums.txt     # numeric sort
uniq file            # collapse ADJACENT duplicate lines
uniq -c file         # ...and prefix each with a count
\`\`\`

\`uniq\` only merges neighbours, so the golden combo is always:

\`\`\`bash
sort file | uniq -c          # counts of every unique line
\`\`\`

## cut — slice by column

\`\`\`bash
cut -d: -f1 /etc/passwd      # field 1 (usernames) using : delimiter
cat /var/log/auth.log | cut -d' ' -f11    # column 11 of each log line
\`\`\`

\`-d\` sets the delimiter, \`-f\` picks fields (1-based).

## tr — translate characters

\`\`\`bash
echo "secret" | tr a-z A-Z        # → SECRET
\`\`\`

## The full analyst chain

Find WHO is attacking: extract the attacker IP from every failed login, count per IP:

\`\`\`bash
grep "Failed password" /var/log/auth.log | cut -d' ' -f11 | sort | uniq -c
\`\`\`

Read that chain right-to-left in your head: filter → slice → sort → count. That single line is used by SOC analysts and attackers every single day.`,
      practice: {
        prompt: 'List all usernames from /etc/passwd: cut field 1 by colon delimiter, then sort them.',
        hints: ['`cat /etc/passwd | cut -d: -f1 | sort`', 'Fields are counted from 1; the delimiter for passwd is the colon.'],
        check: ctx => ranRe(/cut\s+-d:\s+-f1\s+\/etc\/passwd/)(ctx) || (ranRe(/^cat\s+\/etc\/passwd/)(ctx) && ranRe(/\|\s*cut\s+-d:/)(ctx)),
      },
      quiz: [
        { q: 'Why must you sort before uniq?', options: ['For speed', 'uniq only merges adjacent duplicate lines', 'sort deletes duplicates', 'No reason'], answer: 1, explanation: 'uniq collapses only neighbouring identical lines, so sorting first groups them.' },
        { q: 'What does `cut -d: -f1 /etc/passwd` print?', options: ['The password hashes', 'The usernames', 'The first line', 'The UID field'], answer: 1, explanation: 'Split each line on : and keep field 1 = username.' },
        { q: 'What does `sort | uniq -c` produce?', options: ['A random list', 'Unique lines with their counts', 'Sorted numbers', 'Compressed output'], answer: 1, explanation: 'Counts occurrences of every distinct line.' },
        { q: 'What does `echo hi | tr a-z A-Z` print?', options: ['hi', 'HI', 'Hi', 'hI'], answer: 1, explanition: 'tr maps each character in set a-z to its partner in A-Z.' },
      ],
    },
  ],
  lab: {
    id: 'ch2-lab',
    title: 'Lab 2 — Hunt the Attacker',
    brief: 'Your machine (shellstrike) shows signs of a brute-force attack. Use text-processing tools on /var/log/auth.log to reconstruct what happened, and save your findings like a professional.',
    steps: [
      { goal: 'How many lines does the auth log have? Use cat with a pipe into wc -l.', hint: 'cat /var/log/auth.log | wc -l', check: ctx => ranRe(/\/var\/log\/auth\.log\s*\|\s*wc/)(ctx) },
      { goal: 'Show every "Failed password" event in the log.', hint: 'grep "Failed password" /var/log/auth.log', check: ctx => ranRe(/^grep\s+"Failed password"\s+\/var\/log\/auth\.log/)(ctx) },
      { goal: 'Count the total failed password events (just the number).', hint: 'Add the -c flag to grep.', check: ctx => ranRe(/^grep\s+-c\s+"Failed password"/)(ctx) && outputHas('13')(ctx) },
      { goal: 'Is the attacker targeting root? Show only failed logins for user root (grep for "Failed password for root").', hint: 'grep "Failed password for root" /var/log/auth.log — note: plain "for root", not "invalid user"', check: ctx => ranRe(/Failed password for root/)(ctx) && outputHas('Failed password for root from')(ctx) },
      { goal: 'Extract the attacker IPs: pipe the failed logins through cut on space delimiter, field 11, then sort, then uniq -c.', hint: 'grep "Failed password" /var/log/auth.log | cut -d\' \' -f11 | sort | uniq -c', check: ctx => ranRe(/cut\s+-d.\s.\s+-f11/)(ctx) && ranRe(/uniq/)(ctx) && outputHas('10.10.10.99')(ctx) },
      { goal: 'Save the incident summary: write the attacker IP counts to ~/incident.txt using redirection.', hint: 'Append | sort | uniq -c > ~/incident.txt to your grep pipeline.', check: ctx => fileHas('~/incident.txt', '10.10.10.99')(ctx) },
    ],
  },
  cheat: [
    { cmd: 'cmd > file / >> file', desc: 'redirect / append output to file' },
    { cmd: 'cmd < file', desc: 'feed file into command input' },
    { cmd: 'cmd1 | cmd2', desc: 'pipe stdout into next command' },
    { cmd: 'grep "pat" file', desc: 'lines matching pattern' },
    { cmd: 'grep -i / -c / -n / -v', desc: 'ignore case / count / line no / invert' },
    { cmd: 'sort / sort -r / sort -n', desc: 'sort lines / reverse / numeric' },
    { cmd: 'sort | uniq -c', desc: 'count unique lines' },
    { cmd: 'cut -d: -f1', desc: 'field 1 split by colon' },
    { cmd: 'tr a-z A-Z', desc: 'translate characters' },
    { cmd: 'grep "^Sep 13 03" file', desc: 'regex: lines starting with... ' },
  ],
};
