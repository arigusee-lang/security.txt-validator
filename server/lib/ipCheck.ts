/**
 * Checks whether an IP address falls within private/reserved ranges.
 * Blocks RFC 1918, loopback, link-local, and IPv6 equivalents.
 */
export function isBlockedIp(ip: string): boolean {
  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  const v4Mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4Mapped) {
    return isBlockedIpv4(v4Mapped[1]);
  }

  if (ip.includes(":")) {
    return isBlockedIpv6(ip);
  }

  return isBlockedIpv4(ip);
}

function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return true; // malformed ? block
  const nums = parts.map(Number);
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return true;

  const [a, b] = nums;

  // 10.0.0.0/8
  if (a === 10) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 127.0.0.0/8 (loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (link-local)
  if (a === 169 && b === 254) return true;
  // 0.0.0.0
  if (nums.every((n) => n === 0)) return true;

  return false;
}

function expandIpv6(ip: string): string {
  const halves = ip.split("::");
  if (halves.length > 2) return "0000:0000:0000:0000:0000:0000:0000:0000";

  let groups: string[];
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0000");
    groups = [...left, ...middle, ...right];
  } else {
    groups = ip.split(":");
  }

  return groups.map((g) => g.padStart(4, "0")).join(":");
}

function isBlockedIpv6(ip: string): boolean {
  const normalized = expandIpv6(ip).toLowerCase();

  // ::1 (loopback)
  if (normalized === "0000:0000:0000:0000:0000:0000:0000:0001") return true;
  // :: (all zeros)
  if (/^0{4}(:0{4}){7}$/.test(normalized)) return true;
  // fc00::/7 (unique local) — first byte fc or fd
  const firstByte = parseInt(normalized.slice(0, 2), 16);
  if (firstByte >= 0xfc && firstByte <= 0xfd) return true;
  // fe80::/10 (link-local) — first 10 bits are 1111111010
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
      normalized.startsWith("fea") || normalized.startsWith("feb")) return true;

  return false;
}
