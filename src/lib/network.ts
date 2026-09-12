// src/lib/network.ts

// ─── Types ───────────────────────────────────────────────────────────────────

export interface OpenPort {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service: string;
  version: string;
  banner?: string;       // raw banner string returned by netcat
  cpe?: string;          // e.g., 'cpe:/a:apache:http_server:2.4.54'
}

export interface VHost {
  ip: string;
  hostname: string;
  os: string;
  osDetails: string;     // CPE-style, e.g., 'cpe:/o:linux:linux_kernel:5.15'
  mac: string;
  macVendor: string;
  ttl: number;
  ports: OpenPort[];
  isUp: boolean;
}

export interface WebPage {
  path: string;
  statusCode: number;
  contentLength: number;
  contentType: string;
  body: string;
  redirect?: string;
  headers: Record<string, string>;
}

export interface WebServer {
  hostIp: string;
  port: number;
  serverHeader: string;
  pages: Record<string, WebPage>;
}

export interface LoginEndpoint {
  hostIp: string;
  port: number;
  path: string;
  protocol: 'http' | 'https' | 'ssh' | 'ftp' | 'mysql' | 'rdp';
  validCreds: Array<{ user: string; pass: string }>;
  failMessage: string;
  successMessage: string;
}

export interface DnsRecord {
  name: string;
  type: 'A' | 'AAAA' | 'MX' | 'NS' | 'CNAME' | 'TXT' | 'SOA';
  value: string;
  ttl: number;
}

export interface WhoisData {
  domain: string;
  registrar: string;
  creationDate: string;
  expiryDate: string;
  nameServers: string[];
  status: string[];
  registrant: string;
}

export interface VulnParam {
  url: string;
  param: string;
  vulnerable: boolean;
  dbms?: string;
  dbs?: string[];
  tables?: Record<string, string[]>;
  technique?: string;
}

export interface VirtualNetwork {
  hosts: VHost[];
  webServers: WebServer[];
  loginEndpoints: LoginEndpoint[];
  dnsRecords: DnsRecord[];
  whoisData: WhoisData[];
  vulnParams: VulnParam[];
}

// ─── Seeded Random (deterministic per session, looks random) ────────────────

let _seed = 42;
export function seededRandom(): number {
  _seed = (_seed * 16807 + 0) % 2147483647;
  return (_seed - 1) / 2147483646;
}

export function randomInt(min: number, max: number): number {
  return Math.floor(seededRandom() * (max - min + 1)) + min;
}

export function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(seededRandom() * arr.length)];
}

export function randomMac(): string {
  const hex = () => randomInt(0, 255).toString(16).padStart(2, '0');
  return `${hex()}:${hex()}:${hex()}:${hex()}:${hex()}:${hex()}`;
}

// ─── Network Topology ───────────────────────────────────────────────────────

export function createNetwork(): VirtualNetwork {

  // ── Hosts ─────────────────────────────────────────────────────────────────

  const hosts: VHost[] = [
    {
      ip: '10.10.10.5',
      hostname: 'web01.corp.local',
      os: 'Linux 5.15 - 5.19',
      osDetails: 'cpe:/o:linux:linux_kernel:5.15',
      mac: '00:50:56:a3:1b:2c',
      macVendor: 'VMware',
      ttl: 63,
      isUp: true,
      ports: [
        { port: 22, protocol: 'tcp', state: 'open', service: 'ssh',
          version: 'OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)',
          banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n',
          cpe: 'cpe:/a:openbsd:openssh:8.9p1' },
        { port: 80, protocol: 'tcp', state: 'open', service: 'http',
          version: 'Apache httpd 2.4.54 ((Ubuntu))',
          banner: 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n',
          cpe: 'cpe:/a:apache:http_server:2.4.54' },
        { port: 443, protocol: 'tcp', state: 'open', service: 'https',
          version: 'Apache httpd 2.4.54 ((Ubuntu))',
          cpe: 'cpe:/a:apache:http_server:2.4.54' },
        { port: 8080, protocol: 'tcp', state: 'open', service: 'http-proxy',
          version: 'Apache Tomcat/Coyote JSP engine 1.1',
          banner: 'HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n',
          cpe: 'cpe:/a:apache:tomcat:9.0.65' },
        { port: 3306, protocol: 'tcp', state: 'filtered', service: 'mysql',
          version: '', cpe: '' },
      ],
    },
    {
      ip: '10.10.10.10',
      hostname: 'dc01.corp.local',
      os: 'Microsoft Windows Server 2019 Standard',
      osDetails: 'cpe:/o:microsoft:windows_server_2019',
      mac: '00:50:56:a3:4f:81',
      macVendor: 'VMware',
      ttl: 127,
      isUp: true,
      ports: [
        { port: 53, protocol: 'tcp', state: 'open', service: 'domain',
          version: 'Microsoft DNS 10.0.17763', cpe: '' },
        { port: 88, protocol: 'tcp', state: 'open', service: 'kerberos-sec',
          version: 'Microsoft Windows Kerberos (server time: 2026-09-13 10:00:00Z)', cpe: '' },
        { port: 135, protocol: 'tcp', state: 'open', service: 'msrpc',
          version: 'Microsoft Windows RPC', cpe: '' },
        { port: 139, protocol: 'tcp', state: 'open', service: 'netbios-ssn',
          version: 'Microsoft Windows netbios-ssn', cpe: '' },
        { port: 389, protocol: 'tcp', state: 'open', service: 'ldap',
          version: 'Microsoft Windows Active Directory LDAP (Domain: corp.local, Site: Default-First-Site-Name)',
          cpe: 'cpe:/a:microsoft:active_directory' },
        { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds',
          version: 'Windows Server 2019 Standard 17763 microsoft-ds', cpe: '' },
        { port: 464, protocol: 'tcp', state: 'open', service: 'kpasswd5',
          version: '', cpe: '' },
        { port: 636, protocol: 'tcp', state: 'open', service: 'ldapssl',
          version: '', cpe: '' },
        { port: 3268, protocol: 'tcp', state: 'open', service: 'ldap',
          version: 'Microsoft Windows Active Directory LDAP', cpe: '' },
        { port: 3389, protocol: 'tcp', state: 'open', service: 'ms-wbt-server',
          version: 'Microsoft Terminal Services',
          banner: '',
          cpe: 'cpe:/a:microsoft:remote_desktop_protocol' },
      ],
    },
    {
      ip: '10.10.10.20',
      hostname: 'db01.corp.local',
      os: 'Linux 5.4.0-150-generic',
      osDetails: 'cpe:/o:linux:linux_kernel:5.4',
      mac: '00:50:56:a3:7c:3d',
      macVendor: 'VMware',
      ttl: 63,
      isUp: true,
      ports: [
        { port: 22, protocol: 'tcp', state: 'open', service: 'ssh',
          version: 'OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)',
          banner: 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n',
          cpe: 'cpe:/a:openbsd:openssh:7.9p1' },
        { port: 3306, protocol: 'tcp', state: 'open', service: 'mysql',
          version: 'MySQL 8.0.32-0ubuntu0.20.04.2',
          banner: '55\x00\x00\x00\n8.0.32-0ubuntu0.20.04.2\x00',
          cpe: 'cpe:/a:oracle:mysql:8.0.32' },
        { port: 5432, protocol: 'tcp', state: 'open', service: 'postgresql',
          version: 'PostgreSQL 13.10 (Ubuntu 13.10-0ubuntu0.20.04.1)',
          cpe: 'cpe:/a:postgresql:postgresql:13.10' },
      ],
    },
    {
      ip: '10.10.10.50',
      hostname: 'backup.corp.local',
      os: 'Linux 4.19.0-21-amd64',
      osDetails: 'cpe:/o:linux:linux_kernel:4.19',
      mac: '00:50:56:a3:9e:55',
      macVendor: 'VMware',
      ttl: 63,
      isUp: true,
      ports: [
        { port: 21, protocol: 'tcp', state: 'open', service: 'ftp',
          version: 'vsftpd 3.0.3',
          banner: '220 (vsFTPd 3.0.3)\r\n',
          cpe: 'cpe:/a:vsftpd:vsftpd:3.0.3' },
        { port: 22, protocol: 'tcp', state: 'open', service: 'ssh',
          version: 'OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)',
          banner: 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n',
          cpe: 'cpe:/a:openbsd:openssh:7.4p1' },
        { port: 139, protocol: 'tcp', state: 'open', service: 'netbios-ssn',
          version: 'Samba smbd 3.X - 4.X (workgroup: WORKGROUP)', cpe: '' },
        { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds',
          version: 'Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)',
          cpe: 'cpe:/a:samba:samba:4.9.5' },
      ],
    },
    {
      ip: '10.10.10.100',
      hostname: '',
      os: '',
      osDetails: '',
      mac: '',
      macVendor: '',
      ttl: 0,
      isUp: false,
      ports: [],
    },
  ];

  // ── Web Servers ──────────────────────────────────────────────────────────

  const webServers: WebServer[] = [
    {
      hostIp: '10.10.10.5',
      port: 80,
      serverHeader: 'Apache/2.4.54 (Ubuntu)',
      pages: {
        '/': {
          path: '/',
          statusCode: 200,
          contentLength: 1247,
          contentType: 'text/html; charset=UTF-8',
          body: '<!DOCTYPE html>\n<html><head><title>Corp Intranet</title></head>\n<body><h1>Welcome to Corp Intranet</h1>\n<p>Internal use only.</p>\n<a href="/login">Employee Login</a>\n<a href="/about">About</a>\n</body></html>',
          headers: { 'Server': 'Apache/2.4.54 (Ubuntu)', 'X-Powered-By': 'PHP/8.1.2', 'X-Frame-Options': 'SAMEORIGIN' },
        },
        '/login': {
          path: '/login',
          statusCode: 200,
          contentLength: 892,
          contentType: 'text/html; charset=UTF-8',
          body: '<html><body><form action="/login" method="POST">\n<input name="username"><input name="password" type="password">\n<button type="submit">Login</button></form></body></html>',
          headers: { 'Server': 'Apache/2.4.54 (Ubuntu)' },
        },
        '/about': {
          path: '/about',
          statusCode: 200,
          contentLength: 534,
          contentType: 'text/html',
          body: '<html><body><h1>About Corp</h1><p>Founded 2019.</p></body></html>',
          headers: { 'Server': 'Apache/2.4.54 (Ubuntu)' },
        },
        '/robots.txt': {
          path: '/robots.txt',
          statusCode: 200,
          contentLength: 112,
          contentType: 'text/plain',
          body: 'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /api/\nDisallow: /config/\nDisallow: /.git/\n',
          headers: {},
        },
        '/admin': {
          path: '/admin',
          statusCode: 302,
          contentLength: 0,
          contentType: 'text/html',
          body: '',
          redirect: '/login',
          headers: { 'Location': '/login' },
        },
        '/admin/dashboard': {
          path: '/admin/dashboard',
          statusCode: 403,
          contentLength: 199,
          contentType: 'text/html',
          body: '<html><body><h1>403 Forbidden</h1></body></html>',
          headers: {},
        },
        '/api': {
          path: '/api',
          statusCode: 200,
          contentLength: 67,
          contentType: 'application/json',
          body: '{"status":"ok","version":"1.2.0","endpoints":["/api/users","/api/config"]}',
          headers: { 'Content-Type': 'application/json' },
        },
        '/api/users': {
          path: '/api/users',
          statusCode: 401,
          contentLength: 29,
          contentType: 'application/json',
          body: '{"error":"Unauthorized"}',
          headers: {},
        },
        '/api/config': {
          path: '/api/config',
          statusCode: 200,
          contentLength: 145,
          contentType: 'application/json',
          body: '{"db_host":"10.10.10.20","db_user":"app","db_name":"corp_prod","debug":true,"secret_key":"sup3rs3cr3tk3y!!"}',
          headers: {},
        },
        '/backup': {
          path: '/backup',
          statusCode: 403,
          contentLength: 199,
          contentType: 'text/html',
          body: '<html><body><h1>403 Forbidden</h1></body></html>',
          headers: {},
        },
        '/backup/db_dump.sql': {
          path: '/backup/db_dump.sql',
          statusCode: 200,
          contentLength: 4520,
          contentType: 'application/sql',
          body: '-- MySQL dump 10.13\nCREATE TABLE users (\n  id INT PRIMARY KEY,\n  username VARCHAR(50),\n  password VARCHAR(255)\n);\nINSERT INTO users VALUES (1, \'admin\', \'5f4dcc3b5aa765d61d8327deb882cf99\');\nINSERT INTO users VALUES (2, \'jdoe\', \'e99a18c428cb38d5f260853678922e03\');\n',
          headers: {},
        },
        '/config': {
          path: '/config',
          statusCode: 403,
          contentLength: 199,
          contentType: 'text/html',
          body: '<html><body><h1>403 Forbidden</h1></body></html>',
          headers: {},
        },
        '/.git/HEAD': {
          path: '/.git/HEAD',
          statusCode: 200,
          contentLength: 23,
          contentType: 'text/plain',
          body: 'ref: refs/heads/main\n',
          headers: {},
        },
        '/.git/config': {
          path: '/.git/config',
          statusCode: 200,
          contentLength: 210,
          contentType: 'text/plain',
          body: '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = git@github.com:corp-intranet/webapp.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n',
          headers: {},
        },
        '/uploads': {
          path: '/uploads',
          statusCode: 200,
          contentLength: 312,
          contentType: 'text/html',
          body: '<html><body><h1>Index of /uploads</h1><ul><li><a href="report.pdf">report.pdf</a></li><li><a href="shell.php">shell.php</a></li></ul></body></html>',
          headers: {},
        },
        '/server-status': {
          path: '/server-status',
          statusCode: 403,
          contentLength: 199,
          contentType: 'text/html',
          body: '<html><body><h1>403 Forbidden</h1></body></html>',
          headers: {},
        },
        '/wp-admin': { statusCode: 404, contentLength: 274, contentType: 'text/html', body: '<html><body>Not Found</body></html>', headers: {}, path: '/wp-admin' },
        '/phpmyadmin': { statusCode: 404, contentLength: 274, contentType: 'text/html', body: '<html><body>Not Found</body></html>', headers: {}, path: '/phpmyadmin' },
        '/test': { statusCode: 200, contentLength: 145, contentType: 'text/html', body: '<html><body><h1>Test Page</h1></body></html>', headers: {}, path: '/test' },
        '/images': { statusCode: 200, contentLength: 89, contentType: 'text/html', body: '<html><body>Index of /images</body></html>', headers: {}, path: '/images' },
      },
    },
    {
      hostIp: '10.10.10.5',
      port: 8080,
      serverHeader: 'Apache-Coyote/1.1',
      pages: {
        '/': {
          path: '/',
          statusCode: 200,
          contentLength: 1100,
          contentType: 'text/html;charset=UTF-8',
          body: '<html><body><h1>Tomcat Manager</h1><p>Apache Tomcat/9.0.65</p><a href="/manager/html">Manager App</a></body></html>',
          headers: { 'Server': 'Apache-Coyote/1.1' },
        },
        '/manager/html': {
          path: '/manager/html',
          statusCode: 401,
          contentLength: 2478,
          contentType: 'text/html;charset=utf-8',
          body: '<html><body><h1>401 Unauthorized</h1><p>Tomcat Manager Application</p></body></html>',
          headers: { 'WWW-Authenticate': 'Basic realm="Tomcat Manager Application"' },
        },
      },
    },
  ];

  // ── Login Endpoints ──────────────────────────────────────────────────────

  const loginEndpoints: LoginEndpoint[] = [
    {
      hostIp: '10.10.10.5',
      port: 22,
      path: '',
      protocol: 'ssh',
      validCreds: [
        { user: 'hacker', pass: 'shellstrike2026' },
        { user: 'root', pass: 'toor' },
        { user: 'jdoe', pass: 'abc123' },
      ],
      failMessage: 'Permission denied (publickey,password).',
      successMessage: 'Welcome to Ubuntu 22.04.2 LTS',
    },
    {
      hostIp: '10.10.10.5',
      port: 80,
      path: '/login',
      protocol: 'http',
      validCreds: [
        { user: 'admin', pass: 'password' },
        { user: 'jdoe', pass: 'abc123' },
      ],
      failMessage: 'Invalid username or password',
      successMessage: 'Welcome to the dashboard',
    },
    {
      hostIp: '10.10.10.5',
      port: 8080,
      path: '/manager/html',
      protocol: 'http',
      validCreds: [
        { user: 'tomcat', pass: 's3cret' },
      ],
      failMessage: '401 Unauthorized',
      successMessage: 'Tomcat Web Application Manager',
    },
    {
      hostIp: '10.10.10.50',
      port: 21,
      path: '',
      protocol: 'ftp',
      validCreds: [
        { user: 'ftpuser', pass: 'ftpuser' },
        { user: 'anonymous', pass: '' },
      ],
      failMessage: '530 Login incorrect.',
      successMessage: '230 Login successful.',
    },
    {
      hostIp: '10.10.10.20',
      port: 3306,
      path: '',
      protocol: 'mysql',
      validCreds: [
        { user: 'app', pass: 'Sup3rS3cr3tP@ss' },
        { user: 'root', pass: 'mysqlroot123' },
      ],
      failMessage: 'Access denied for user',
      successMessage: 'Welcome to the MySQL monitor.',
    },
  ];

  // ── DNS Records ──────────────────────────────────────────────────────────

  const dnsRecords: DnsRecord[] = [
    { name: 'corp.local', type: 'SOA', value: 'dc01.corp.local. admin.corp.local. 2026091301 3600 900 604800 86400', ttl: 3600 },
    { name: 'corp.local', type: 'NS', value: 'dc01.corp.local.', ttl: 86400 },
    { name: 'corp.local', type: 'NS', value: 'dc02.corp.local.', ttl: 86400 },
    { name: 'corp.local', type: 'MX', value: '10 mail.corp.local.', ttl: 3600 },
    { name: 'web01.corp.local', type: 'A', value: '10.10.10.5', ttl: 3600 },
    { name: 'dc01.corp.local', type: 'A', value: '10.10.10.10', ttl: 3600 },
    { name: 'dc02.corp.local', type: 'A', value: '10.10.10.11', ttl: 3600 },
    { name: 'db01.corp.local', type: 'A', value: '10.10.10.20', ttl: 3600 },
    { name: 'backup.corp.local', type: 'A', value: '10.10.10.50', ttl: 3600 },
    { name: 'mail.corp.local', type: 'A', value: '10.10.10.30', ttl: 3600 },
    { name: 'mail.corp.local', type: 'MX', value: '10 mail.corp.local.', ttl: 3600 },
    { name: 'www.corp.local', type: 'CNAME', value: 'web01.corp.local.', ttl: 3600 },
    { name: 'corp.local', type: 'TXT', value: '"v=spf1 include:_spf.google.com ~all"', ttl: 3600 },
    { name: 'internal.corp.local', type: 'A', value: '10.10.10.200', ttl: 3600 },
    { name: 'dev.corp.local', type: 'A', value: '10.10.10.60', ttl: 3600 },
    { name: 'staging.corp.local', type: 'A', value: '10.10.10.70', ttl: 3600 },
    { name: 'git.corp.local', type: 'A', value: '10.10.10.80', ttl: 3600 },
    { name: 'vpn.corp.local', type: 'A', value: '10.10.10.2', ttl: 3600 },
  ];

  // ── Whois Data ───────────────────────────────────────────────────────────

  const whoisData: WhoisData[] = [
    {
      domain: 'corp.local',
      registrar: 'Internal Corporate Registrar',
      creationDate: '2019-03-15T08:00:00Z',
      expiryDate: '2029-03-15T08:00:00Z',
      nameServers: ['dc01.corp.local', 'dc02.corp.local'],
      status: ['clientTransferProhibited', 'clientUpdateProhibited'],
      registrant: 'Corp Industries Ltd.',
    },
  ];

  // ── Vulnerable Parameters (for sqlmap) ─────────────────────────────────

  const vulnParams: VulnParam[] = [
    {
      url: 'http://10.10.10.5/login',
      param: 'username',
      vulnerable: true,
      dbms: 'MySQL',
      dbs: ['information_schema', 'corp_prod', 'mysql', 'performance_schema'],
      tables: {
        'corp_prod': ['users', 'sessions', 'products', 'orders', 'logs'],
        'mysql': ['user', 'db', 'tables_priv'],
      },
      technique: 'boolean-based blind',
    },
    {
      url: 'http://10.10.10.5/api/users',
      param: 'id',
      vulnerable: true,
      dbms: 'MySQL',
      dbs: ['information_schema', 'corp_prod'],
      tables: {
        'corp_prod': ['users', 'sessions'],
      },
      technique: 'UNION query',
    },
    {
      url: 'http://10.10.10.5/about',
      param: 'page',
      vulnerable: false,
    },
  ];

  return {
    hosts,
    webServers,
    loginEndpoints,
    dnsRecords,
    whoisData,
    vulnParams,
  };
}

// ─── Lookup Helpers ──────────────────────────────────────────────────────────

export function findHost(net: VirtualNetwork, ip: string): VHost | undefined {
  return net.hosts.find(h => h.ip === ip);
}

export function findHostByName(net: VirtualNetwork, hostname: string): VHost | undefined {
  return net.hosts.find(h => h.hostname === hostname);
}

export function resolveToIp(net: VirtualNetwork, target: string): string | null {
  // Direct IP
  if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) return target;
  // Hostname lookup
  const host = findHostByName(net, target);
  if (host) return host.ip;
  // DNS A record lookup
  const record = net.dnsRecords.find(r => r.name === target && r.type === 'A');
  if (record) return record.value;
  return null;
}

export function findWebServer(net: VirtualNetwork, ip: string, port: number): WebServer | undefined {
  return net.webServers.find(w => w.hostIp === ip && w.port === port);
}

export function findWebPage(net: VirtualNetwork, ip: string, port: number, path: string): WebPage | undefined {
  const server = findWebServer(net, ip, port);
  if (!server) return undefined;
  // Normalize path
  const normalized = path === '' ? '/' : (path.startsWith('/') ? path : '/' + path);
  return server.pages[normalized];
}

export function findLoginEndpoint(net: VirtualNetwork, ip: string, port: number, protocol: string): LoginEndpoint | undefined {
  return net.loginEndpoints.find(e =>
    e.hostIp === ip && e.port === port && e.protocol === protocol
  );
}

export function checkCredentials(net: VirtualNetwork, ip: string, port: number, protocol: string, user: string, pass: string): { success: boolean; message: string } {
  const endpoint = findLoginEndpoint(net, ip, port, protocol);
  if (!endpoint) {
    return { success: false, message: `Connection refused on ${ip}:${port}` };
  }
  const valid = endpoint.validCreds.some(c => c.user === user && c.pass === pass);
  if (valid) {
    return { success: true, message: endpoint.successMessage };
  }
  return { success: false, message: endpoint.failMessage };
}

export function findDnsRecords(net: VirtualNetwork, name: string, type?: string): DnsRecord[] {
  return net.dnsRecords.filter(r =>
    r.name === name && (!type || r.type === type.toUpperCase())
  );
}

export function findWhois(net: VirtualNetwork, domain: string): WhoisData | undefined {
  return net.whoisData.find(w => w.domain === domain || domain.endsWith(w.domain));
}

export function findVulnParam(net: VirtualNetwork, url: string, param: string): VulnParam | undefined {
  return net.vulnParams.find(v => v.url === url && v.param === param);
}
