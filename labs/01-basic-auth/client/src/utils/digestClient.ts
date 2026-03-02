/**
 * Digest Auth client implementation
 * Handles the full challenge-response flow automatically:
 * 1. Send initial request → receive 401 with WWW-Authenticate: Digest ...
 * 2. Parse nonce, realm, qop from header
 * 3. Compute MD5 hash response
 * 4. Retry request with Authorization: Digest ...
 */

async function md5(message: string): Promise<string> {
  // Use Web Crypto API for MD5 via a simple implementation
  // Note: Web Crypto doesn't support MD5 natively (it's deprecated for security)
  // We implement a lightweight MD5 for Digest Auth compatibility
  return md5Impl(message);
}

/** Lightweight MD5 implementation for browser (no external deps) */
function md5Impl(str: string): string {
  function safeAdd(x: number, y: number): number {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function bitRotateLeft(num: number, cnt: number): number {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5cmn(
    q: number,
    a: number,
    b: number,
    x: number,
    s: number,
    t: number,
  ): number {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  function md5ff(
    a: number,
    b: number,
    c: number,
    d: number,
    x: number,
    s: number,
    t: number,
  ): number {
    return md5cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function md5gg(
    a: number,
    b: number,
    c: number,
    d: number,
    x: number,
    s: number,
    t: number,
  ): number {
    return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function md5hh(
    a: number,
    b: number,
    c: number,
    d: number,
    x: number,
    s: number,
    t: number,
  ): number {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function md5ii(
    a: number,
    b: number,
    c: number,
    d: number,
    x: number,
    s: number,
    t: number,
  ): number {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  const utf8Str = unescape(encodeURIComponent(str));
  const length8 = utf8Str.length;
  const remainder = length8 % 64;
  const paddingLength = remainder < 56 ? 56 - remainder : 120 - remainder;
  const paddedLength = length8 + paddingLength + 8;

  const words: number[] = new Array(paddedLength / 4).fill(0);
  for (let i = 0; i < length8; i++) {
    words[i >> 2] |= utf8Str.charCodeAt(i) << ((i % 4) * 8);
  }
  words[length8 >> 2] |= 0x80 << ((length8 % 4) * 8);
  words[paddedLength / 4 - 2] = length8 * 8;

  let a = 1732584193,
    b = -271733879,
    c = -1732584194,
    d = 271733878;

  for (let i = 0; i < words.length; i += 16) {
    const [oa, ob, oc, od] = [a, b, c, d];
    a = md5ff(a, b, c, d, words[i], 7, -680876936);
    d = md5ff(d, a, b, c, words[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, words[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, words[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, words[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, words[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, words[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, words[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, words[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, words[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, words[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, words[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, words[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, words[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, words[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, words[i + 15], 22, 1236535329);
    a = md5gg(a, b, c, d, words[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, words[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, words[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, words[i], 20, -373897302);
    a = md5gg(a, b, c, d, words[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, words[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, words[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, words[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, words[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, words[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, words[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, words[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, words[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, words[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, words[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, words[i + 12], 20, -1926607734);
    a = md5hh(a, b, c, d, words[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, words[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, words[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, words[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, words[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, words[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, words[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, words[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, words[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, words[i], 11, -358537222);
    c = md5hh(c, d, a, b, words[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, words[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, words[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, words[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, words[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, words[i + 2], 23, -995338651);
    a = md5ii(a, b, c, d, words[i], 6, -198630844);
    d = md5ii(d, a, b, c, words[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, words[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, words[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, words[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, words[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, words[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, words[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, words[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, words[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, words[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, words[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, words[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, words[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, words[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, words[i + 9], 21, -343485551);
    a = safeAdd(a, oa);
    b = safeAdd(b, ob);
    c = safeAdd(c, oc);
    d = safeAdd(d, od);
  }

  const result = [a, b, c, d];
  return result
    .map((n) =>
      Array.from({ length: 4 }, (_, i) =>
        ((n >> (i * 8)) & 0xff).toString(16).padStart(2, "0"),
      ).join(""),
    )
    .join("");
}

function generateCnonce(): string {
  return (
    Math.random().toString(36).substring(2) +
    Math.random().toString(36).substring(2)
  );
}

function parseWWWAuthenticateDigest(header: string): Record<string, string> {
  const params: Record<string, string> = {};
  const regex = /(\w+)=(?:"([^"]*)"|([^,\s]*))/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(header)) !== null) {
    params[match[1]] = match[2] !== undefined ? match[2] : match[3];
  }
  return params;
}

export interface DigestAuthResult {
  ok: boolean;
  status: number;
  data: unknown;
  steps: DigestStep[];
}

export interface DigestStep {
  label: string;
  detail: string;
  type: "request" | "response" | "compute" | "success" | "error";
}

/**
 * Perform a full Digest Auth request with step tracking for visualization
 */
export async function digestAuthFetch(
  url: string,
  username: string,
  password: string,
): Promise<DigestAuthResult> {
  const steps: DigestStep[] = [];

  // ── Step 1: Initial unauthenticated request ──
  steps.push({
    label: "Initial Request",
    detail: `GET ${url} (no credentials)`,
    type: "request",
  });

  const res1 = await fetch(url);

  if (res1.status !== 401) {
    const data = await res1.json();
    return { ok: res1.ok, status: res1.status, data, steps };
  }

  const wwwAuth = res1.headers.get("WWW-Authenticate") || "";
  steps.push({
    label: "Server Challenge (401)",
    detail: wwwAuth,
    type: "response",
  });

  // ── Step 2: Parse challenge ──
  const params = parseWWWAuthenticateDigest(wwwAuth);
  const { realm, nonce, qop, opaque } = params;
  const algorithm = params.algorithm || "MD5";

  // ── Step 3: Compute hash ──
  const cnonce = generateCnonce();
  const nc = "00000001";
  const method = "GET";
  const uri = new URL(url, window.location.origin).pathname;

  const HA1 = await md5(`${username}:${realm}:${password}`);
  const HA2 = await md5(`${method}:${uri}`);

  steps.push({
    label: "Compute HA1",
    detail: `MD5("${username}:${realm}:<password>") = ${HA1.substring(0, 8)}...`,
    type: "compute",
  });
  steps.push({
    label: "Compute HA2",
    detail: `MD5("${method}:${uri}") = ${HA2.substring(0, 8)}...`,
    type: "compute",
  });

  let responseHash: string;
  if (qop === "auth") {
    responseHash = await md5(`${HA1}:${nonce}:${nc}:${cnonce}:${qop}:${HA2}`);
    steps.push({
      label: "Compute Response Hash",
      detail: `MD5("HA1:${nonce.substring(0, 8)}...:${nc}:cnonce:auth:HA2") = ${responseHash.substring(0, 8)}...`,
      type: "compute",
    });
  } else {
    responseHash = await md5(`${HA1}:${nonce}:${HA2}`);
    steps.push({
      label: "Compute Response Hash",
      detail: `MD5("HA1:nonce:HA2") = ${responseHash.substring(0, 8)}...`,
      type: "compute",
    });
  }

  // ── Step 4: Build Authorization header ──
  let authHeader = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", algorithm=${algorithm}, response="${responseHash}"`;
  if (qop) authHeader += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (opaque) authHeader += `, opaque="${opaque}"`;

  steps.push({
    label: "Authenticated Request",
    detail: `GET ${url} with Digest Authorization header`,
    type: "request",
  });

  // ── Step 5: Authenticated request ──
  const res2 = await fetch(url, {
    headers: { Authorization: authHeader },
  });

  const data = await res2.json();

  if (res2.ok) {
    steps.push({
      label: "Authentication Successful!",
      detail: `Status 200 OK`,
      type: "success",
    });
  } else {
    steps.push({
      label: "Authentication Failed",
      detail: `Status ${res2.status}`,
      type: "error",
    });
  }

  return { ok: res2.ok, status: res2.status, data, steps };
}
