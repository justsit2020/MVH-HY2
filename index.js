#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const https = require('https');
const { spawn, spawnSync } = require('child_process');

process.umask(0o077);

const PORT = process.env.PORT ? Number(process.env.PORT) : 14421; 
const SNI_HOST = 'www.bing.com'; 

const BASE_DIR = '/home/container/.hy2';
const BIN = path.join(BASE_DIR, 'hysteria');
const CONF = path.join(BASE_DIR, 'config.yaml');
const STATE = path.join(BASE_DIR, 'state.env');
const CERT = path.join(BASE_DIR, 'cert.pem');
const KEY = path.join(BASE_DIR, 'key.pem');
const NODEFILE = path.join(BASE_DIR, 'node.txt');
const LOG = path.join(BASE_DIR, 'hysteria.log');
const LOCKFILE = path.join(BASE_DIR, 'runner.lock');

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function fatal(msg) {
  log(`[fatal] ${msg}`);

  return new Promise(() => {});
}

function isProcessAlive(pid) {
  if (!pid || !Number.isFinite(pid)) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true, mode: 0o700 });
}

function writeFileSecure(filePath, content, mode = 0o600) {
  fs.writeFileSync(filePath, content, { mode });
}

function readTextIfExists(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function hasExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function opensslAvailable() {
  const r = spawnSync('openssl', ['version'], { stdio: 'ignore' });
  return r.status === 0;
}

function runOpenSSL(args, opts = {}) {
  const r = spawnSync('openssl', args, {
    encoding: 'utf8',
    ...opts,
  });
  return r;
}

async function fetchText(url) {
  return new Promise((resolve) => {
    const request = (u, redirectsLeft = 5) => {
      https
        .get(u, (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location &&
            redirectsLeft > 0
          ) {
            res.resume();
            return request(res.headers.location, redirectsLeft - 1);
          }

          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            res.resume();
            return resolve('');
          }

          let data = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => resolve(data.trim()));
        })
        .on('error', () => resolve(''));
    };

    request(url);
  });
}

async function downloadToFile(url, destPath, mode = 0o700) {
  await new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath, { mode: 0o600 }); 
    const request = (u, redirectsLeft = 5) => {
      https
        .get(u, (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location &&
            redirectsLeft > 0
          ) {
            res.resume();
            return request(res.headers.location, redirectsLeft - 1);
          }

          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            res.resume();
            file.close(() => reject(new Error(`HTTP ${res.statusCode || 'ERR'}`)));
            return;
          }

          res.pipe(file);
          file.on('finish', () => file.close(resolve));
        })
        .on('error', (err) => {
          try {
            file.close(() => {});
          } catch {}
          reject(err);
        });
    };
    request(url);
  });

  fs.chmodSync(destPath, mode);
}

function pickAsset() {
  const arch = os.arch(); 
  if (arch === 'x64') {
    let cpuinfo = '';
    try {
      cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8').toLowerCase();
    } catch {}
    const hasAvx = cpuinfo.includes(' avx ');
    return hasAvx ? 'hysteria-linux-amd64-avx' : 'hysteria-linux-amd64';
  }
  if (arch === 'arm64') return 'hysteria-linux-arm64';
  if (arch === 'arm') return 'hysteria-linux-arm';
  if (arch === 'ia32') return 'hysteria-linux-386';

  if (arch === 'riscv64') return 'hysteria-linux-riscv64';
  if (arch === 's390x') return 'hysteria-linux-s390x';

  return '';
}

ensureDir(BASE_DIR);
const logStream = fs.createWriteStream(LOG, { flags: 'a', mode: 0o600 });
function log(line) {
  const msg = typeof line === 'string' ? line : String(line);
  process.stdout.write(msg + '\n');
  logStream.write(msg + '\n');
}

process.on('uncaughtException', (e) => {
  log(`[uncaughtException] ${e?.stack || e}`);
});
process.on('unhandledRejection', (e) => {
  log(`[unhandledRejection] ${e?.stack || e}`);
});

(async () => {
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    await fatal(`invalid PORT=${process.env.PORT}`);
    return;
  }

  log(`[init] base_dir=${BASE_DIR} port=${PORT} sni=${SNI_HOST}`);

  if (fs.existsSync(LOCKFILE)) {
    const prev = readTextIfExists(LOCKFILE).trim();
    const prevPid = Number(prev);
    if (isProcessAlive(prevPid)) {
      log(`[lock] another runner is active (pid=${prevPid}). keep-alive wait...`);
      while (isProcessAlive(prevPid)) {
        await sleep(30_000);
      }
      log(`[lock] previous runner exited; continue...`);
    } else {
      log('[lock] stale lock found; removing.');
      try {
        fs.unlinkSync(LOCKFILE);
      } catch {}
    }
  }

  writeFileSecure(LOCKFILE, String(process.pid) + '\n', 0o600);

  const cleanup = () => {
    try {
      fs.unlinkSync(LOCKFILE);
    } catch {}
    try {
      logStream.end();
    } catch {}
  };
  process.on('exit', cleanup);

  if (!fs.existsSync(STATE)) {
    const AUTH_PASS = crypto.randomBytes(18).toString('hex'); 
    const NODE_NAME = `hy2-${crypto.randomBytes(3).toString('hex')}`;
    const content = `AUTH_PASS='${AUTH_PASS}'\nNODE_NAME='${NODE_NAME}'\n`;
    writeFileSecure(STATE, content, 0o600);
  }

  const stateTxt = readTextIfExists(STATE);
  const authMatch = stateTxt.match(/AUTH_PASS='([^']+)'/);
  const nameMatch = stateTxt.match(/NODE_NAME='([^']+)'/);
  const AUTH_PASS = authMatch?.[1] || '';
  const NODE_NAME = nameMatch?.[1] || 'hy2-node';

  if (!AUTH_PASS) {
    await fatal('STATE exists but AUTH_PASS missing');
    return;
  }

  const asset = pickAsset();
  if (!asset) {
    await fatal(`unsupported arch: ${os.arch()}`);
    return;
  }

  if (!hasExecutable(BIN)) {
    const url = `https://download.hysteria.network/app/latest/${asset}`;
    log(`[dl] ${url}`);
    try {
      await downloadToFile(url, BIN, 0o700);
    } catch (e) {
      await fatal(`download failed: ${e?.message || e}`);
      return;
    }
  }

  if (!opensslAvailable()) {
    await fatal('openssl not found; cannot generate/validate cert');
    return;
  }

  let needCert = false;
  if (!fs.existsSync(CERT) || !fs.existsSync(KEY)) {
    needCert = true;
  } else {
    const r = runOpenSSL(['x509', '-in', CERT, '-noout', '-text']);
    const txt = (r.stdout || '') + (r.stderr || '');
    if (!txt.includes(`DNS:${SNI_HOST}`)) {
      log(`[tls] cert SAN does not include DNS:${SNI_HOST}; regenerating.`);
      needCert = true;
    }
  }

  if (needCert) {
    log(`[tls] generating self-signed cert with SAN=DNS:${SNI_HOST}`);

    const r1 = runOpenSSL(
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        KEY,
        '-out',
        CERT,
        '-days',
        '3650',
        '-subj',
        `/CN=${SNI_HOST}`,
        '-addext',
        `subjectAltName=DNS:${SNI_HOST}`,
      ],
      { stdio: 'ignore' }
    );

    if (r1.status !== 0) {
      const cnf = path.join(BASE_DIR, 'openssl_san.cnf');
      const cnfTxt = `[req]
distinguished_name=req_dn
x509_extensions=v3_req
prompt=no
[req_dn]
CN=${SNI_HOST}
[v3_req]
subjectAltName=DNS:${SNI_HOST}
`;
      writeFileSecure(cnf, cnfTxt, 0o600);

      const r2 = runOpenSSL(
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          KEY,
          '-out',
          CERT,
          '-days',
          '3650',
          '-config',
          cnf,
        ],
        { stdio: 'ignore' }
      );

      if (r2.status !== 0) {
        await fatal('failed to generate cert');
        return;
      }
    }
  }

  const fp = runOpenSSL(['x509', '-noout', '-fingerprint', '-sha256', '-in', CERT], {
    encoding: 'utf8',
  });
  const fpTxt = (fp.stdout || '').trim();
  const eqIdx = fpTxt.indexOf('=');
  const pinRaw = eqIdx >= 0 ? fpTxt.slice(eqIdx + 1).trim() : '';
  if (!pinRaw) {
    await fatal('failed to read sha256 fingerprint from cert');
    return;
  }
  const pinEsc = encodeURIComponent(pinRaw); // ":" -> %3A

  const confYaml = `listen: :${PORT}

tls:
  cert: ${CERT}
  key: ${KEY}
  sniGuard: strict

auth:
  type: password
  password: ${AUTH_PASS}
`;
  writeFileSecure(CONF, confYaml, 0o600);

  let host = (process.env.NODE_HOST || '').trim();
  if (!host) host = (await fetchText('https://api.ipify.org')) || '';
  if (!host) host = 'your_host';

  const uriPinned = `hy2://${AUTH_PASS}@${host}:${PORT}/?insecure=1&pinSHA256=${pinEsc}&sni=${SNI_HOST}#${NODE_NAME}`;
  const uriBasic = `hy2://${AUTH_PASS}@${host}:${PORT}/?insecure=1&sni=${SNI_HOST}#${NODE_NAME}`;

  const nodeTxt = `Pinned (recommended): ${uriPinned}
Basic:              ${uriBasic}

Notes:
- sni/insecure/pinSHA256 are URI parameters defined by Hysteria 2 URI Scheme.
`;
  writeFileSecure(NODEFILE, nodeTxt, 0o600);

  log(`[node] saved: ${NODEFILE}`);
  log(`[node] pinned: ${uriPinned}`);
  log(`[node] basic : ${uriBasic}`);

  let child = null;
  let stopping = false;

  async function stop() {
    if (stopping) return;
    stopping = true;
    log('[signal] stopping...');
    if (child && !child.killed) {
      try {
        child.kill('SIGTERM');
      } catch {}
    } else {
      process.exit(0);
    }
  }

  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  let backoff = 2;

  while (true) {
    log('[run] starting hysteria server...');

    child = spawn(BIN, ['server', '-c', CONF], { stdio: ['ignore', 'pipe', 'pipe'] });

    child.stdout.on('data', (d) => {
      process.stdout.write(d);
      logStream.write(d);
    });
    child.stderr.on('data', (d) => {
      process.stderr.write(d);
      logStream.write(d);
    });

    const rc = await new Promise((resolve) => {
      child.on('exit', (code, signal) => resolve({ code, signal }));
      child.on('error', (err) => resolve({ code: 1, signal: `error:${err?.message || err}` }));
    });

    child = null;

    if (stopping) {
      process.exit(0);
      return;
    }

    log(`[run] hysteria exited (code=${rc.code} signal=${rc.signal || ''}). backoff=${backoff}s`);
    await sleep(backoff * 1000);
    if (backoff < 30) backoff = Math.min(backoff * 2, 30);
  }
})().catch(async (e) => {
  await fatal(e?.stack || String(e));
});

