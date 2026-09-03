const dns = require('node:dns').promises;
const net = require('node:net');
const { RiskLevel, ViolationRecord } = require('./models');

class SSRFGuard {
  constructor(options = {}) {
    this.blockedDomains = [
      'metadata.google.internal',
      'instance-data',
      'metadata.azure.com',
      '169.254.169.254.nip.io',
      'localhost',
      '127.0.0.1.nip.io'
    ];
  }

  isPrivateOrLoopback(ip) {
    if (net.isIPv4(ip)) {
      const parts = ip.split('.').map(Number);
      // 127.0.0.0/8 loopback
      if (parts[0] === 127) return true;
      // 169.254.0.0/16 link-local & cloud IMDS (169.254.169.254)
      if (parts[0] === 169 && parts[1] === 254) return true;
      // 10.0.0.0/8 private
      if (parts[0] === 10) return true;
      // 172.16.0.0/12 private
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      // 192.168.0.0/16 private
      if (parts[0] === 192 && parts[1] === 168) return true;
      // 0.0.0.0/8 current network
      if (parts[0] === 0) return true;
      return false;
    } else if (net.isIPv6(ip)) {
      const lower = ip.toLowerCase().replace(/[\[\]]/g, '');
      if (lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc00:')) return true;
      // IPv4 mapped IPv6 (::ffff:169.254.169.254 or ::ffff:a9fe:a9fe)
      if (lower.startsWith('::ffff:')) {
        const v4part = lower.replace('::ffff:', '');
        if (v4part.includes(':')) {
          const hexParts = v4part.split(':');
          if (hexParts.length === 2) {
            const n1 = parseInt(hexParts[0], 16);
            const n2 = parseInt(hexParts[1], 16);
            const dotV4 = [(n1 >> 8) & 255, n1 & 255, (n2 >> 8) & 255, n2 & 255].join('.');
            return this.isPrivateOrLoopback(dotV4);
          }
        }
        return this.isPrivateOrLoopback(v4part);
      }
      return false;
    }
    return false;
  }

  parseOctalOrHex(host) {
    const clean = host.replace(/[\[\]]/g, '');
    if (/^0x[0-9a-fA-F]+$/i.test(clean)) {
      const num = parseInt(clean, 16);
      if (num >= 0 && num <= 0xFFFFFFFF) {
        return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
      }
    }
    if (/^\d+$/.test(clean)) {
      const num = parseInt(clean, 10);
      if (num >= 0 && num <= 0xFFFFFFFF) {
        return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
      }
    }
    const parts = clean.split('.');
    if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
      const norm = parts.map(p => (p.startsWith('0') && p.length > 1 ? parseInt(p, 8) : parseInt(p, 10)));
      return norm.join('.');
    }
    return clean;
  }

  inspectArguments(args) {
    const strings = this._extractStrings(args);
    const violations = [];
    for (const s of strings) {
      const v = this.checkString(s);
      if (v) violations.push(v);
    }
    return violations;
  }

  _extractStrings(data) {
    const out = [];
    if (typeof data === 'string') {
      out.push(data);
    } else if (Array.isArray(data)) {
      for (const item of data) out.push(...this._extractStrings(item));
    } else if (data && typeof data === 'object') {
      for (const val of Object.values(data)) out.push(...this._extractStrings(val));
    }
    return out;
  }

  checkString(raw) {
    const s = raw.trim();
    let hostname = null;

    try {
      if (/^[a-zA-Z][a-zA-Z0-9+-.]*:\/\//.test(s)) {
        const u = new URL(s);
        hostname = u.hostname;
      }
    } catch (e) {}

    if (!hostname && !s.includes(' ') && s.length < 256) {
      if (/^[0-9a-fA-F.:\[\]]+(?::\d+)?$/.test(s) || s === 'localhost') {
        hostname = s.split(':')[0].replace(/[\[\]]/g, '');
      }
    }

    if (!hostname) return null;

    const lowerHost = hostname.toLowerCase();

    // 1. Blocked domain check
    for (const d of this.blockedDomains) {
      if (lowerHost === d || lowerHost.endsWith('.' + d)) {
        return new ViolationRecord(
          'ssrf_blocked_domain',
          RiskLevel.CRITICAL,
          `Destination domain '${hostname}' matches blocked infrastructure metadata endpoint.`
        );
      }
    }

    // 2. Direct IP / Octal / Hex check
    const cleanHost = lowerHost.replace(/[\[\]]/g, '');
    const normalizedIp = this.parseOctalOrHex(cleanHost);
    if (this.isPrivateOrLoopback(normalizedIp)) {
      return new ViolationRecord(
        'ssrf_blocked_network_range',
        RiskLevel.CRITICAL,
        `Target IP address '${normalizedIp}' falls within forbidden network range (private/loopback/cloud metadata).`
      );
    }

    return null;
  }

  async resolveAndVerify(hostname, port = 80) {
    const cleanHost = hostname.replace(/[\[\]]/g, '');
    try {
      const addresses = await dns.lookup(cleanHost, { all: true });
      for (const item of addresses) {
        if (this.isPrivateOrLoopback(item.address)) {
          return {
            isValid: false,
            pinnedIp: item.address,
            violation: new ViolationRecord(
              'ssrf_blocked_network_range',
              RiskLevel.CRITICAL,
              `Target host '${hostname}' resolved to forbidden IP '${item.address}' (private/metadata range).`
            ),
          };
        }
      }
      return { isValid: true, pinnedIp: addresses[0].address, violation: null };
    } catch (e) {
      return {
        isValid: false,
        pinnedIp: null,
        violation: new ViolationRecord('ssrf_dns_error', RiskLevel.HIGH, `DNS lookup failed for '${hostname}': ${e.message}`),
      };
    }
  }

  async openPinnedConnection(urlString, timeoutMs = 10000) {
    const u = new URL(urlString);
    const port = u.port || (u.protocol === 'https:' ? 443 : 80);
    const { isValid, pinnedIp, violation } = await this.resolveAndVerify(u.hostname, port);
    if (!isValid || !pinnedIp) {
      throw new Error(`SSRF Blocked: ${violation ? violation.reason : 'Unsafe host'}`);
    }

    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: pinnedIp, port: Number(port), timeout: timeoutMs }, () => {
        resolve({ socket, pinnedIp });
      });
      socket.on('error', reject);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Connection timed out'));
      });
    });
  }
}

module.exports = { SSRFGuard };
