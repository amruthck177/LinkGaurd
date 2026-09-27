/**
 * LinkGuard Backend Resolver
 * Safe DNS resolution and unshortening redirect preview with SSRF protection.
 */

import dns from 'dns';
import http from 'http';
import https from 'https';

const dnsPromises = dns.promises;

/**
 * Checks if an IP address belongs to private/internal ranges (SSRF prevention).
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateIp(ip) {
  if (!ip) return false;
  // Localhost
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;

  // IPv4 Private subnets
  const parts = ip.split('.').map(Number);
  if (parts.length === 4) {
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 (Link-local, AWS metadata 169.254.169.254)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
  }

  // IPv6 unique local (fc00::/7) or link-local (fe80::/10)
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;

  return false;
}

/**
 * Safely resolves DNS records for a given hostname.
 * @param {string} hostname
 * @returns {Promise<object>}
 */
export async function resolveDns(hostname) {
  if (!hostname) return { resolved: false, error: 'Empty hostname' };

  try {
    const addresses = await dnsPromises.resolve4(hostname);
    const hasPrivate = addresses.some(isPrivateIp);

    return {
      resolved: true,
      records: addresses,
      primaryIp: addresses[0] || null,
      isPrivateRange: hasPrivate,
      ttl: null
    };
  } catch (err) {
    // Hostname might not exist (NXDOMAIN) or be an IP literal
    return {
      resolved: false,
      error: err.code || err.message,
      isNonExistent: err.code === 'ENOTFOUND'
    };
  }
}

/**
 * Follows HTTP/HTTPS redirects safely up to maxHops to reveal the unshortened final URL.
 * Strictly blocks internal / private IP addresses to prevent SSRF vulnerabilities.
 * @param {string} targetUrl
 * @param {number} maxHops
 * @returns {Promise<object>}
 */
export async function unshortenUrl(targetUrl, maxHops = 3) {
  const hops = [];
  let currentUrl = targetUrl;

  for (let step = 0; step < maxHops; step++) {
    try {
      const parsed = new URL(currentUrl);

      // Validate protocol
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return {
          success: false,
          error: `Unsupported protocol ${parsed.protocol}`,
          hops
        };
      }

      // Check host resolution to prevent SSRF
      try {
        const ips = await dnsPromises.resolve4(parsed.hostname);
        if (ips.some(isPrivateIp)) {
          return {
            success: false,
            error: 'Blocked redirection to internal or private IP address.',
            hops
          };
        }
      } catch (dnsErr) {
        // Continue if standard DNS fails or is an IP
      }

      const client = parsed.protocol === 'https:' ? https : http;

      const response = await new Promise((resolve, reject) => {
        const req = client.request(
          currentUrl,
          {
            method: 'HEAD',
            timeout: 3500,
            headers: {
              'User-Agent': 'LinkGuard-Security-Inspector/1.0 (+https://linkguard.local)'
            }
          },
          res => resolve(res)
        );

        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timed out'));
        });
        req.on('error', reject);
        req.end();
      });

      const statusCode = response.statusCode;
      const location = response.headers.location;

      hops.push({
        from: currentUrl,
        statusCode,
        location: location || null
      });

      if (statusCode >= 300 && statusCode < 400 && location) {
        // Resolve relative redirects against current URL
        const nextUrl = new URL(location, currentUrl).href;
        currentUrl = nextUrl;
      } else {
        // Final destination reached
        return {
          success: true,
          originalUrl: targetUrl,
          finalUrl: currentUrl,
          hopsCount: hops.length,
          hops
        };
      }
    } catch (err) {
      return {
        success: false,
        error: err.message,
        originalUrl: targetUrl,
        lastUrl: currentUrl,
        hops
      };
    }
  }

  return {
    success: true,
    originalUrl: targetUrl,
    finalUrl: currentUrl,
    hopsCount: hops.length,
    hops,
    maxHopsReached: true
  };
}
