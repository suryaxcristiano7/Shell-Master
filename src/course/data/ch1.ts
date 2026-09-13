// src/course/data/ch1.ts — Chapter 1: Linux & Shell Foundations
import type { Chapter } from '../types';
import { ran, ranRe, outputHas, fileExists, dirExists, isRoot } from '../checks';

export const ch1: Chapter = {
  id: 'ch1',
  number: 1,
  title: 'Linux & Shell Foundations',
  tagline: 'Your attack platform: the terminal',
  lessons: [
    {
      id: 'ch1-l1',
      title: 'Welcome to the Shell',
      minutes: 8,
      content: `## What is this black box?

Every hacker's journey starts in the **terminal**. A terminal is a window where you type commands, and a **shell** (usually \`bash\`) is the program that reads them and makes things happen.

You are running a simulated **Kali Linux** machine — the same distribution professional penetration testers use. Its user is called \`hacker\` and the machine is named \`shellstrike\`.

> The prompt \`┌──(hacker㉿shellstrike)-[~]\` tells you: which user, on which machine, in which folder. Read it every time you sit down — real attackers often get caught because they typed in the wrong window!

## Your first commands

Type these in the terminal below — each one prints information:

\`\`\`bash
whoami        # who am I logged in as?
hostname      # name of this machine
uname         # operating system
date          # current date and time
echo "hi"      # print text to the screen
\`\`\`

\`echo\` is the "print" of the shell — you will use it in almost every script you ever write.

## Flags and arguments

Most commands accept **options** (also called flags) that change behaviour:

\`\`\`bash
uname -a       # -a = "all" info: kernel, hostname, architecture
\`\`\`

A flag usually starts with a dash: \`-a\`, \`-l\`, \`-la\`. Later, tools like \`nmap\` will take many flags at once — start reading them carefully now.`,
      chart: 'linuxstack',
      practice: {
        prompt: 'Run `whoami` to confirm which user you are operating as.',
        hints: ['Just type `whoami` and press Enter.'],
        check: ctx => ran('whoami')(ctx) && outputHas('hacker')(ctx),
      },
      quiz: [
        { q: 'What does the shell do?', options: ['It renders web pages', 'It reads your commands and executes them', 'It stores your files', 'It encrypts traffic'], answer: 1, explanation: 'The shell (bash) interprets the commands you type and runs them.' },
        { q: 'Which command prints text to the screen?', options: ['print', 'echo', 'show', 'display'], answer: 1, explanation: 'echo "text" prints its arguments — the workhorse of bash scripting.' },
        { q: 'What does `uname -a` show?', options: ['Only the username', 'All logged-in users', 'Full system/kernel information', 'The current directory'], answer: 2, explanation: '-a (all) shows kernel name, hostname, version and architecture.' },
      ],
    },
    {
      id: 'ch1-l2',
      title: 'Navigating the Filesystem',
      minutes: 12,
      content: `## One tree to rule them all

Linux organises everything into a single tree starting at **/ (root)** — no C:\\ drives, no drive letters.

\`\`\`bash
pwd            # print working directory — where am I?
cd /etc        # change directory to /etc (absolute path)
cd             # bare cd goes to your home (~)
cd ..          # go UP one level
cd tools       # go DOWN into tools/ (relative to where you are)
\`\`\`

\`~\` is shorthand for your home directory (\`/home/hacker\`).

## Listing files

\`\`\`bash
ls             # list the current directory
ls /etc        # list a specific directory
ls -l          # long format: permissions, owner, size, date
ls -la         # -a also shows hidden files (starting with .)
\`\`\`

In \`ls -l\`, the first column like \`drwxr-xr-x\` is the **permission string** — the next lesson of this chapter decodes it.

## Where hackers look first

- \`/etc\` — system configuration (\`passwd\`, \`hosts\`)
- \`/var/log\` — logs, including \`auth.log\` (login attempts!)
- \`/home\` and \`/root\` — user files
- \`/usr/share/wordlists\` — password wordlists for brute-forcing

> Attackers navigate by keyboard because it is faster. Muscle-memory \`ls -la\` on every directory you enter.`,
      chart: 'dirTree',
      practice: {
        prompt: 'Navigate into /etc and list its contents with `ls -la`. (The check passes when your current directory is /etc and you have run a long listing there.)',
        hints: ['Two commands are needed: `cd /etc` then `ls -la`.', 'Absolute paths start with / — so `cd /etc` from anywhere.'],
        check: ctx => ctx.state.vfs.cwd === '/etc' && ran('ls -la')(ctx),
      },
      quiz: [
        { q: 'What does `pwd` print?', options: ['The password file', 'Your current working directory', 'Your username', 'The list of files'], answer: 1, explanation: 'pwd = print working directory.' },
        { q: 'Which command moves you into /var/log?', options: ['mv /var/log', 'cd /var/log', 'goto /var/log', 'ls /var/log'], answer: 1, explanation: 'cd = change directory.' },
        { q: 'In ls -l output, what does a leading "d" in drwxr-xr-x mean?', options: ['The file is deleted', 'It is a directory', 'It is a driver', 'It is downloadable'], answer: 1, explanation: 'The first character of the permission string is the type: d = directory, - = regular file.' },
        { q: 'What does `cd ..` do?', options: ['Goes to the root directory', 'Goes up one directory level', 'Deletes the parent directory', 'Repeats the last command'], answer: 1, explanation: '.. always means the parent directory.' },
      ],
    },
    {
      id: 'ch1-l3',
      title: 'Creating & Manipulating Files',
      minutes: 12,
      content: `## Build, copy, move, destroy

\`\`\`bash
touch notes.txt          # create an empty file
mkdir reports           # create a directory
mkdir -p a/b/c          # create nested directories in one shot
cp notes.txt copy.txt    # copy a file
mv notes.txt old.txt     # rename (move) a file
mv old.txt reports/      # move it into a directory
rm copy.txt             # delete a file — no recycle bin!
rm -r reports           # delete a directory AND its contents
\`\`\`

> There is **no trash can**. \`rm\` is forever — in the real world a mistyped \`rm -r\` has deleted entire companies. Always \`ls\` before you \`rm\`.

## Wildcards

\`\`\`bash
ls *.txt        # every .txt file
rm *.log        # every .log file
\`\`\`

\`*\` matches anything — you will use it constantly with tools like \`find\`.

## Writing content into a file

The next chapter covers redirection in depth, but you need one trick now:

\`\`\`bash
echo "target: 10.10.10.5" > target.txt    # write (overwrites!)
cat target.txt                           # read it back
\`\`\`

\`>\` sends the output of \`echo\` into the file instead of the screen.`,
      practice: {
        prompt: 'Create a directory called `labs` inside your home directory, then create an empty file `labs/targets.txt` inside it.',
        hints: ['`mkdir ~/labs` first (or `mkdir -p ~/labs`).', 'Then `touch ~/labs/targets.txt` — the ~ is your home.'],
        check: ctx => dirExists('~/labs')(ctx) && fileExists('~/labs/targets.txt')(ctx),
      },
      quiz: [
        { q: 'Which command creates an empty file?', options: ['mkdir file', 'touch file', 'new file', 'create file'], answer: 1, explanation: 'touch creates the file (or updates its timestamp if it exists).' },
        { q: 'How do you create nested directories a/b/c in one command?', options: ['mkdir a/b/c', 'mkdir -p a/b/c', 'mkdir -n a/b/c', 'touch a/b/c'], answer: 1, explanation: '-p creates every missing parent directory.' },
        { q: 'What does `echo "hi" > f.txt` do?', options: ['Prints hi and creates nothing', 'Writes hi into f.txt, replacing its old content', 'Appends hi to f.txt', 'Renames f.txt'], answer: 1, explanation: '> redirects output INTO the file, overwriting. >> appends instead.' },
        { q: 'What is the danger of `rm -r`?', options: ['It is recursive and permanent', 'It requires root', 'It only works on directories', 'Nothing, it is safe'], answer: 0, explanation: 'It removes a directory tree completely — no trash can.' },
      ],
    },
    {
      id: 'ch1-l4',
      title: 'Reading Files',
      minutes: 10,
      content: `## cat, head, tail, wc

Files you can read are files you can learn from — especially config and log files.

\`\`\`bash
cat /etc/passwd             # print the WHOLE file
head -n 5 /etc/passwd        # first 5 lines
tail -n 3 /etc/passwd        # last 3 lines
wc -l /etc/passwd            # count lines
\`\`\`

## Why /etc/passwd matters

Every user on a Linux box has a line here:

\`\`\`
root:x:0:0:root:/root:/bin/bash
hacker:x:1000:1000:Hacker,,,:/home/hacker:/bin/bash
\`\`\`

Fields (split by \`:\`): **username : x : uid : gid : description : home : shell**.

- \`root\` has **UID 0** — the superuser.
- Usernames here are your first map of the target: who exists, what shells they get.

## Quick tastes

\`cat\` is fine for small files. For huge logs you will soon combine \`head\`, \`tail\` and \`grep\` (next chapter) to pull out only what matters — like failed SSH logins.

> Field position matters: \`/etc/passwd\` line 7 is the user's shell. If it is /usr/sbin/nologin, that user can't get a shell.`,
      practice: {
        prompt: 'Read /etc/passwd and find out whether a user named `hacker` exists on this machine (use `cat` and read the output).',
        hints: ['`cat /etc/passwd` prints all users.', 'Look for the line starting with `hacker:`.'],
        check: ctx => ranRe(/^cat\s+\/etc\/passwd/)(ctx) && outputHas('hacker:x:1000')(ctx),
      },
      quiz: [
        { q: 'Which command shows only the first 10 lines of a file?', options: ['first file', 'head file', 'top file', 'cat -10 file'], answer: 1, explanation: 'head shows the beginning (10 lines by default, or -n N for N lines).' },
        { q: 'In /etc/passwd, what is UID 0?', options: ['A disabled user', 'The root superuser', 'A system group', 'The guest account'], answer: 1, explanation: 'UID 0 is always root — the account attackers want.' },
        { q: 'What does `wc -l file` print?', options: ['The file size', 'The number of lines', 'The last line', 'Word count only'], answer: 1, explanation: 'wc -l counts lines (-w words, -c characters).' },
      ],
    },
    {
      id: 'ch1-l5',
      title: 'Users, Permissions & sudo',
      minutes: 15,
      content: `## The permission string

Run \`ls -l\` and you will see strings like \`-rw-r--r--\`:

\`\`\`
-    rw-      r--      r--
type owner   group   others
\`\`\`

- **owner** — the user who owns the file
- **group** — users in the file's group
- **others** — everyone else

Each triad is **r**ead (4), **w**rite (2), e**x**ecute (1). Octal shorthand: \`755\` = rwxr-xr-x.

## Changing permissions & ownership

\`\`\`bash
chmod 755 script.sh       # owner rwx, everyone else r-x
chmod 600 secret.key       # owner rw- only
chown root backup.tar      # change owner (needs root)
\`\`\`

A file must be **executable** (\`x\`) to run as a program — remember this when you write scripts.

## sudo — do as root

Some files are protected, like \`/etc/shadow\` (password hashes, readable by root only):

\`\`\`bash
cat /etc/shadow           # Permission denied
sudo cat /etc/shadow      # root's power, temporarily
sudo bash                 # stay root until you exit
\`\`\`

\`sudo\` runs a single command as root. \`sudo bash\` drops you into a root shell — the moment an attacker dreams of.

> As a defender: \`sudo\` usage is logged in /var/log/auth.log. As an attacker: it is often the fastest path to privilege escalation.`,
      chart: 'permissions',
      practice: {
        prompt: 'Prove you can read the password hashes: read /etc/shadow with root privileges using `sudo cat /etc/shadow`.',
        hints: ['Prefix the command with sudo: `sudo cat /etc/shadow`.', 'You are looking for lines starting with root:$6$ and hacker:$6$.'],
        check: ctx => ranRe(/^sudo\s+cat\s+\/etc\/shadow/)(ctx) && outputHas('$6$')(ctx),
      },
      quiz: [
        { q: 'What does chmod 600 file do?', options: ['Everyone can read and write', 'Owner read+write, nobody else', 'Owner execute only', 'Makes it a directory'], answer: 1, explanation: '6 = rw- for owner, 0 = nothing for group and others.' },
        { q: 'Why can a normal user NOT read /etc/shadow?', options: ['The file is encrypted', 'File permissions allow root/group only', 'It is too large', 'It does not exist'], answer: 1, explanation: 'Its permissions (-rw-r-----) restrict reading to root and the shadow group.' },
        { q: 'What does `sudo bash` give you?', options: ['A new user account', 'A root shell', 'A backup of bash', 'A list of sudoers'], answer: 1, explanation: 'It starts a shell as root — full control of the machine.' },
        { q: 'Which octal digit means "read + execute but not write"?', options: ['7', '6', '5', '3'], answer: 2, explanation: '5 = 4 (read) + 1 (execute).' },
      ],
    },
  ],
  lab: {
    id: 'ch1-lab',
    title: 'Lab 1 — Ground Zero',
    brief: 'You just got access to a Kali box. Explore it like an attacker casing a target: identify yourself, read the operator\'s notes, and capture your first flag by becoming root.',
    steps: [
      { goal: 'Confirm who you are logged in as.', hint: 'whoami', check: ctx => ran('whoami')(ctx) && outputHas('hacker')(ctx) },
      { goal: 'Read the operator\'s recon notes in your home directory (notes.txt).', hint: 'cat ~/notes.txt — it contains plans against target.corp.local', check: ctx => ranRe(/^cat\s+(~\/notes|notes\.txt|\/home\/hacker\/notes)/)(ctx) && outputHas('RECON NOTES')(ctx) },
      { goal: 'List the /etc directory in long format to see system config files.', hint: 'ls -la /etc (or cd /etc first, then ls -la)', check: ctx => ran('ls -la /etc')(ctx) || (ctx.state.vfs.cwd === '/etc' && ran('ls -la')(ctx)) },
      { goal: 'Read /etc/passwd and confirm the target machine has a root and a hacker account.', hint: 'cat /etc/passwd', check: ctx => ranRe(/^cat\s+\/etc\/passwd/)(ctx) && outputHas('root:x:0:0')(ctx) },
      { goal: 'Take a user-level flag: read ~/flag.txt.', hint: 'cat ~/flag.txt — it starts with flag{', check: ctx => outputHas('flag{w3lc0me')(ctx) },
      { goal: 'Escalate: become root with a root shell.', hint: 'sudo bash', check: ctx => isRoot(ctx) },
      { goal: 'Read the root-only flag at /root/flag.txt.', hint: 'You are root now — just cat /root/flag.txt', check: ctx => outputHas('flag{r00t_1s_th3_g0al')(ctx) },
    ],
  },
  cheat: [
    { cmd: 'whoami / hostname', desc: 'current user / machine name' },
    { cmd: 'uname -a', desc: 'kernel & system info' },
    { cmd: 'pwd', desc: 'print working directory' },
    { cmd: 'ls -la [dir]', desc: 'list all files, long format' },
    { cmd: 'cd <dir> | cd .. | cd ~', desc: 'change directory' },
    { cmd: 'touch <file>', desc: 'create empty file' },
    { cmd: 'mkdir -p a/b/c', desc: 'create nested directories' },
    { cmd: 'cp / mv / rm -r', desc: 'copy, move/rename, delete' },
    { cmd: 'cat / head -n / tail -n', desc: 'read files (all / start / end)' },
    { cmd: 'wc -l', desc: 'count lines' },
    { cmd: 'chmod 755 / 600', desc: 'set permissions (rwx=4+2+1)' },
    { cmd: 'sudo cat / sudo bash', desc: 'run as root / get root shell' },
    { cmd: 'cat /etc/passwd', desc: 'enumerate users' },
    { cmd: 'sudo cat /etc/shadow', desc: 'read password hashes' },
  ],
};
