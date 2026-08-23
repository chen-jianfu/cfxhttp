import { connect } from 'cloudflare:sockets';

let proxyIP = '{colo}.proxyip.cmliussss.net, ProxyIP.Multacom.CMLiussss.net';  // 回退地址，支持 {colo} 占位符（运行时替换为机房代码）与逗号分隔多地址顺序兜底
let yourUUID = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63';
let 调试日志打印 = false;
let 预加载竞速拨号 = false;
let TCP并发拨号数 = 2;
let 反代并发拨号数 = 1;
let 连接超时毫秒 = 1000;

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const WS早期数据最大字节 = 8 * 1024, WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;
const 上行合包目标字节 = 20 * 1024, 上行队列最大字节 = 16 * 1024 * 1024, 上行队列最大条目 = 4096;
const 下行Grain包字节 = 32 * 1024, 下行Grain尾部阈值 = 512, 下行Grain低水位字节 = Math.max(4096, 下行Grain尾部阈值 * 12), 下行Grain最大等待轮次 = 4;

function log(...args) {
    if (调试日志打印) console.log(...args);
}

function closeSocketQuietly(socket) {
    try { if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) { socket.close(); }
    } catch (error) {}
}

function 数据转Uint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data || 0);
}

function 有效数据长度(data) {
    if (!data) return 0;
    if (typeof data.byteLength === 'number') return data.byteLength;
    if (typeof data.length === 'number') return data.length;
    return 0;
}

async function WebSocket发送并等待(webSocket, payload) {
    const sendResult = webSocket.send(payload);
    if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function concatBytes(a, b) {
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(a, 0);
    out.set(b, a.byteLength);
    return out;
}

function stripIPv6Brackets(hostname = '') {
    const host = String(hostname || '').trim();
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPv4(value) {
    const parts = String(value || '').split('.');
    return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isIPHostname(hostname = '') {
    const host = stripIPv6Brackets(hostname);
    const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    if (ipv4Regex.test(host)) return true;
    if (!host.includes(':')) return false;
    try {
        new URL(`http://[${host}]/`);
        return true;
    } catch (e) {
        return false;
    }
}

const DoH缓存 = {};
const DoH缓存最大条目 = 256;
const DoH记录类型映射 = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
    const 规范化域名 = String(域名 || '').trim().toLowerCase().replace(/\.$/, '');
    const 规范化记录类型 = String(记录类型 || '').trim().toUpperCase();
    const 缓存键 = `${规范化域名}:${规范化记录类型}`;
    const qtype = DoH记录类型映射[规范化记录类型] || 1;
    const 当前时间戳 = Date.now();
    const 现缓存项 = DoH缓存[缓存键];
    if (现缓存项 && 当前时间戳 < 现缓存项.过期时间) {
        log(`[DoH查询] 命中缓存 ${域名} ${记录类型}`);
        return 现缓存项.data.map(data => ({ type: qtype, data }));
    }
    const 开始时间 = performance.now();
    log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
    try {
        const 编码域名 = (name) => {
            const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
            const bufs = [];
            for (const label of parts) {
                const enc = new TextEncoder().encode(label);
                bufs.push(new Uint8Array([enc.length]), enc);
            }
            bufs.push(new Uint8Array([0]));
            const total = bufs.reduce((s, b) => s + b.length, 0);
            const result = new Uint8Array(total);
            let off = 0;
            for (const b of bufs) { result.set(b, off); off += b.length }
            return result;
        };

        const qname = 编码域名(规范化域名);
        const query = new Uint8Array(12 + qname.length + 4);
        const qview = new DataView(query.buffer);
        qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
        qview.setUint16(2, 0x0100);
        qview.setUint16(4, 1);
        query.set(qname, 12);
        qview.setUint16(12 + qname.length, qtype);
        qview.setUint16(12 + qname.length + 2, 1);

        const response = await fetch(DoH解析服务, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message',
            },
            body: query,
        });
        if (!response.ok) {
            log(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
            return [];
        }

        const buf = new Uint8Array(await response.arrayBuffer());
        const dv = new DataView(buf.buffer);
        const qdcount = dv.getUint16(4);
        const ancount = dv.getUint16(6);
        log(`[DoH查询] 收到响应 ${域名} ${记录类型} (${buf.length}字节, ${ancount}条应答)`);

        const 解析域名 = (pos) => {
            const labels = [];
            let p = pos, jumped = false, endPos = -1, safe = 128;
            while (p < buf.length && safe-- > 0) {
                const len = buf[p];
                if (len === 0) { if (!jumped) endPos = p + 1; break }
                if ((len & 0xC0) === 0xC0) {
                    if (!jumped) endPos = p + 2;
                    p = ((len & 0x3F) << 8) | buf[p + 1];
                    jumped = true;
                    continue;
                }
                labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
                p += len + 1;
            }
            if (endPos === -1) endPos = p + 1;
            return [labels.join('.'), endPos];
        };

        let offset = 12;
        for (let i = 0; i < qdcount; i++) {
            const [, end] = 解析域名(offset);
            offset = end + 4;
        }

        const answers = [];
        for (let i = 0; i < ancount && offset < buf.length; i++) {
            const [name, nameEnd] = 解析域名(offset);
            offset = nameEnd;
            const type = dv.getUint16(offset); offset += 2;
            offset += 2;
            const ttl = dv.getUint32(offset); offset += 4;
            const rdlen = dv.getUint16(offset); offset += 2;
            const rdata = buf.slice(offset, offset + rdlen);
            offset += rdlen;

            let data;
            if (type === 1 && rdlen === 4) {
                data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
            } else if (type === 28 && rdlen === 16) {
                const segs = [];
                for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
                data = segs.join(':');
            } else if (type === 16) {
                let tOff = 0;
                const parts = [];
                while (tOff < rdlen) {
                    const tLen = rdata[tOff++];
                    parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
                    tOff += tLen;
                }
                data = parts.join('');
            } else if (type === 5) {
                const [cname] = 解析域名(offset - rdlen);
                data = cname;
            } else {
                data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            answers.push({ name, type, TTL: ttl, data });
        }
        const 耗时 = (performance.now() - 开始时间).toFixed(2);
        log(`[DoH查询] 查询完成 ${域名} ${记录类型} ${耗时}ms 共${answers.length}条结果`);
        const 相关记录 = answers.filter(answer => answer.type === qtype);
        const 最小TTL = 相关记录.length > 0 ? Math.min(...相关记录.map(a => a.TTL)) : 0;
        const 缓存TTL = Math.max(最小TTL, 5 * 60);
        const 缓存过期时间 = Date.now() + 缓存TTL * 1000;
        const 缓存数据 = 相关记录.map(answer => answer.data);
        if (缓存数据.length > 0 || answers.length === 0) {
            if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
                const 清理时间戳 = Date.now();
                for (const [缓存条目键, 缓存条目] of Object.entries(DoH缓存)) {
                    if (清理时间戳 >= 缓存条目.过期时间) delete DoH缓存[缓存条目键];
                }
                if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
                    delete DoH缓存[Object.keys(DoH缓存)[0]];
                }
            }
            DoH缓存[缓存键] = { data: 缓存数据, 过期时间: 缓存过期时间 };
        }
        return answers;
    } catch (error) {
        log(`[DoH查询] 查询失败 ${域名} ${记录类型}: ${error?.message || error}`);
        return [];
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }
    const lastColonIndex = serverStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const port = parseInt(serverStr.substring(lastColonIndex + 1), 10);

        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    return { type: 'direct', host: serverStr, port: 443 };
}

async function sha224(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  let H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const msgLen = data.length;
  const bitLen = msgLen * 8;
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen, false);
  for (let chunk = 0; chunk < paddedLen; chunk += 64) {
    const W = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(chunk + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }
  const result = [];
  for (let i = 0; i < 7; i++) {
    result.push(
      ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
      ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
      ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
      (H[i] & 0xff).toString(16).padStart(2, '0')
    );
  }
  return result.join('');
}

function rightRotate(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

function 解码WS早期数据(header, sha224PasswordHex) {
    if (!header) return null;
    if (header.length > WS早期数据最大头长度) throw new Error('early data is too large');

    let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    if (padding) normalized += '='.repeat(4 - padding);
    let binaryString;
    try {
        binaryString = atob(normalized);
    } catch (_) {
        return null;
    }
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);

    if (bytes.byteLength > WS早期数据最大字节) throw new Error('early data is too large');
    if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return null;
    for (let i = 0; i < 56; i++) {
        if (bytes[i] !== sha224PasswordHex.charCodeAt(i)) return null;
    }
    return bytes;
}

async function handleTroRequest(request, customProxyIP) {
    const wssPair = new WebSocketPair();
    const clientSock = wssPair[0];
    const serverSock = wssPair[1];
    try { serverSock.accept({ allowHalfOpen: true }) } catch (_) { serverSock.accept() }
    serverSock.binaryType = 'arraybuffer';
    const 密码哈希 = await sha224(yourUUID);
    let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve(), downlinkController: null };
    const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
    let isDnsQuery = false;
    const udpContext = { cache: new Uint8Array(0) };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    let WS显式传输链 = Promise.resolve();
    let WS显式传输停止接收 = false, WS显式传输失败 = false, WS显式传输收尾已入队 = false;
    let WS显式队列字节 = 0, WS显式队列条目 = 0;
    let 当前写入Socket = null, 远端写入器 = null;

    const 释放远端写入器 = () => {
        if (远端写入器) {
            try { 远端写入器.releaseLock() } catch (e) { }
            远端写入器 = null;
        }
        当前写入Socket = null;
    };

    const 上行写入队列 = 创建上行写入队列({
        获取写入器: () => {
            const socket = remoteConnWrapper.socket;
            if (!socket) return null;
            if (socket !== 当前写入Socket) {
                释放远端写入器();
                当前写入Socket = socket;
                远端写入器 = socket.writable.getWriter();
            }
            return 远端写入器;
        },
        获取连接任务: () => remoteConnWrapper.connectingPromise,
        释放写入器: 释放远端写入器,
        重试连接: async () => {
            if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
            await remoteConnWrapper.retryConnect();
        },
        关闭连接: err => 处理WS显式传输错误(err),
        名称: 'WS上行'
    });

    const 处理WS入站数据 = async (chunk) => {
        if (isDnsQuery) return await forwardTrojanUDP(chunk, serverSock, udpContext);
        if (await 上行写入队列.写入(chunk)) return;

        const bytes = 数据转Uint8Array(chunk);
        const 解析结果 = parsetroHeader(bytes, 密码哈希);
        if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
        const { port, hostname, rawClientData, isUDP } = 解析结果;
        log(`[WS转发] Trojan首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
        if (isUDP) {
            isDnsQuery = true;
            if (有效数据长度(rawClientData) > 0) return await forwardTrojanUDP(rawClientData, serverSock, udpContext);
            return;
        }
        await forwardataTCP(hostname, port, rawClientData, serverSock, remoteConnWrapper, customProxyIP);
    };

    const 处理WS显式传输错误 = (err) => {
        if (WS显式传输失败) return;
        WS显式传输失败 = true;
        WS显式传输停止接收 = true;
        WS显式队列字节 = 0;
        WS显式队列条目 = 0;
        const msg = err?.message || `${err}`;
        if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
            log(`[WS转发] 连接结束: ${msg}`);
        } else {
            log(`[WS转发] 处理失败: ${msg}`);
        }
        上行写入队列.清空();
        释放远端写入器();
        失效远端连接();
        closeSocketQuietly(serverSock);
    };

    const 追加WS显式传输任务 = (任务) => {
        WS显式传输链 = WS显式传输链.then(任务).catch(处理WS显式传输错误);
        return WS显式传输链;
    };

    const 入队WS显式传输 = (data) => {
        if (WS显式传输停止接收 || WS显式传输失败) return;
        const chunkSize = Math.max(0, 有效数据长度(data));
        const nextBytes = WS显式队列字节 + chunkSize;
        const nextItems = WS显式队列条目 + 1;
        if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
            处理WS显式传输错误(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
            return;
        }
        WS显式队列字节 = nextBytes;
        WS显式队列条目 = nextItems;
        追加WS显式传输任务(async () => {
            WS显式队列字节 = Math.max(0, WS显式队列字节 - chunkSize);
            WS显式队列条目 = Math.max(0, WS显式队列条目 - 1);
            if (WS显式传输失败) return;
            await 处理WS入站数据(data);
        });
    };

    const 收尾WS显式传输 = () => {
        if (WS显式传输收尾已入队) return;
        WS显式传输收尾已入队 = true;
        WS显式传输停止接收 = true;
        追加WS显式传输任务(async () => {
            if (WS显式传输失败) return;
            await 上行写入队列.等待空();
            释放远端写入器();
            失效远端连接();
        });
    };

    serverSock.addEventListener('message', (event) => {
        入队WS显式传输(event.data);
    });
    serverSock.addEventListener('close', () => {
        closeSocketQuietly(serverSock);
        收尾WS显式传输();
    });
    serverSock.addEventListener('error', (err) => {
        处理WS显式传输错误(err);
    });

    if (earlyDataHeader) {
        try {
            const bytes = 解码WS早期数据(earlyDataHeader, 密码哈希);
            if (bytes?.byteLength) 入队WS显式传输(bytes.buffer);
        } catch (error) {
            处理WS显式传输错误(error);
        }
    }

    return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

function parsetroHeader(data, sha224PasswordHex) {
    data = 数据转Uint8Array(data);
    if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
    let crLfIndex = 56;
    if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
    for (let i = 0; i < crLfIndex; i++) {
        if (data[i] !== sha224PasswordHex.charCodeAt(i)) return { hasError: true, message: "invalid password" };
    }

    const socks5Index = crLfIndex + 2;
    if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

    const cmd = data[socks5Index];
    if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
    const isUDP = cmd === 3;

    const atype = data[socks5Index + 1];
    let addressLength = 0;
    let addressIndex = socks5Index + 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
            address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
            break;
        case 3:
            if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
            addressLength = data[addressIndex];
            addressIndex += 1;
            if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
            address = new TextDecoder().decode(data.subarray(addressIndex, addressIndex + addressLength));
            break;
        case 4:
            addressLength = 16;
            if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                const partIndex = addressIndex + i * 2;
                ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }

    const portIndex = addressIndex + addressLength;
    if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
    const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        isUDP,
        rawClientData: data.subarray(portIndex + 4)
    };
}

async function forwardTrojanUDP(chunk, webSocket, context) {
    const currentChunk = 数据转Uint8Array(chunk);
    const input = context.cache.byteLength ? concatBytes(context.cache, currentChunk) : currentChunk;
    let cursor = 0;

    while (cursor < input.byteLength) {
        const packetStart = cursor;
        const atype = input[cursor];
        let addrCursor = cursor + 1;
        let addrLen = 0;
        if (atype === 1) addrLen = 4;
        else if (atype === 4) addrLen = 16;
        else if (atype === 3) {
            if (input.byteLength < addrCursor + 1) break;
            addrLen = 1 + input[addrCursor];
        } else throw new Error(`invalid trojan udp addressType: ${atype}`);

        const portCursor = addrCursor + addrLen;
        if (input.byteLength < portCursor + 6) break;

        const port = (input[portCursor] << 8) | input[portCursor + 1];
        const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
        if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

        const payloadStart = portCursor + 6;
        const payloadEnd = payloadStart + payloadLength;
        if (input.byteLength < payloadEnd) break;

        const addrPortHeader = input.slice(packetStart, portCursor + 2);
        const payload = input.slice(payloadStart, payloadEnd);
        cursor = payloadEnd;

        if (port !== 53) throw new Error('UDP is not supported');
        if (!payload.byteLength) continue;

        let tcpDNSQuery = payload;
        if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
            tcpDNSQuery = new Uint8Array(payload.byteLength + 2);
            tcpDNSQuery[0] = (payload.byteLength >>> 8) & 0xff;
            tcpDNSQuery[1] = payload.byteLength & 0xff;
            tcpDNSQuery.set(payload, 2);
        }

        const dnsRespContext = { cache: new Uint8Array(0) };
        await forwardDnsOverTcp(tcpDNSQuery, webSocket, (respChunk) => {
            const respBlock = 数据转Uint8Array(respChunk);
            const respInput = dnsRespContext.cache.byteLength ? concatBytes(dnsRespContext.cache, respBlock) : respBlock;
            const frames = [];
            let rc = 0;
            while (rc + 2 <= respInput.byteLength) {
                const dnsLen = (respInput[rc] << 8) | respInput[rc + 1];
                const dnsStart = rc + 2;
                const dnsEnd = dnsStart + dnsLen;
                if (dnsEnd > respInput.byteLength) break;
                const dnsPayload = respInput.slice(dnsStart, dnsEnd);
                const frame = new Uint8Array(addrPortHeader.byteLength + 4 + dnsPayload.byteLength);
                frame.set(addrPortHeader, 0);
                frame[addrPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
                frame[addrPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
                frame[addrPortHeader.byteLength + 2] = 0x0d;
                frame[addrPortHeader.byteLength + 3] = 0x0a;
                frame.set(dnsPayload, addrPortHeader.byteLength + 4);
                frames.push(frame);
                rc = dnsEnd;
            }
            dnsRespContext.cache = respInput.slice(rc);
            return frames.length ? frames : new Uint8Array(0);
        });
    }

    context.cache = input.slice(cursor);
}

async function forwardDnsOverTcp(dnsQuery, webSocket, responseWrapper) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        const writer = tcpSocket.writable.getWriter();
        await writer.write(dnsQuery);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(respChunk) {
                if (webSocket.readyState !== WS_READY_STATE_OPEN) return;
                const result = responseWrapper ? await responseWrapper(respChunk) : respChunk;
                const fragments = Array.isArray(result) ? result : [result];
                for (const fragment of fragments) {
                    const data = 数据转Uint8Array(fragment);
                    if (data.byteLength) await WebSocket发送并等待(webSocket, data);
                }
            },
        }));
    } catch (error) {
        log(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
    }
}

function 创建Grain收纳器(容量, 复制合包结果 = false) {
    let 队列 = [];
    let 头 = 0;
    let 字节数 = 0;
    let 合包缓冲 = null;

    const 为空 = () => 头 >= 队列.length;
    const 压缩 = () => {
        if (头 > 32 && 头 * 2 >= 队列.length) {
            队列 = 队列.slice(头);
            头 = 0;
        }
    };
    const 取出 = () => {
        if (为空()) return null;
        const item = 队列[头];
        队列[头++] = undefined;
        字节数 -= item.chunk.byteLength;
        压缩();
        return item;
    };

    return {
        get 字节数() { return 字节数 },
        get 条目数() { return 队列.length - 头 },
        get 为空() { return 为空() },
        清空(处理项目 = null) {
            if (处理项目) {
                for (let i = 头; i < 队列.length; i++) {
                    if (队列[i]) 处理项目(队列[i]);
                }
            }
            队列 = [];
            头 = 0;
            字节数 = 0;
        },
        收纳(item) {
            if (!item?.chunk?.byteLength) return false;
            队列.push(item);
            字节数 += item.chunk.byteLength;
            return true;
        },
        合包() {
            const first = 取出();
            if (!first) return null;
            const items = [first];
            if (为空() || first.chunk.byteLength >= 容量) return { chunk: first.chunk, items };

            let totalBytes = first.chunk.byteLength;
            let end = 头;
            while (end < 队列.length) {
                const nextBytes = totalBytes + 队列[end].chunk.byteLength;
                if (nextBytes > 容量) break;
                totalBytes = nextBytes;
                end++;
            }
            if (end === 头) return { chunk: first.chunk, items };

            const output = (合包缓冲 ||= new Uint8Array(容量));
            output.set(first.chunk, 0);
            let offset = first.chunk.byteLength;
            while (头 < end) {
                const next = 队列[头];
                队列[头++] = undefined;
                字节数 -= next.chunk.byteLength;
                items.push(next);
                output.set(next.chunk, offset);
                offset += next.chunk.byteLength;
            }
            压缩();
            const bundled = output.subarray(0, totalBytes);
            return { chunk: 复制合包结果 ? bundled.slice() : bundled, items };
        }
    };
}

function 创建上行写入队列({ 获取写入器, 获取连接任务 = null, 释放写入器, 重试连接, 关闭连接, 名称 = '上行队列' }) {
    const grain = 创建Grain收纳器(上行合包目标字节);
    let draining = false;
    let closed = false;
    let idleResolvers = [];
    let activeCompletions = null;

    const settleCompletions = (completions, err = null) => {
        if (!completions) return;
        for (const completion of completions) {
            if (err) completion.reject(err);
            else completion.resolve();
        }
    };

    const resolveIdle = () => {
        if (grain.字节数 || draining || !idleResolvers.length) return;
        const resolvers = idleResolvers;
        idleResolvers = [];
        for (const resolve of resolvers) resolve();
    };

    const clear = (err = null) => {
        const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
        if (closeErr) {
            grain.清空(item => settleCompletions(item.completions, closeErr));
            settleCompletions(activeCompletions, closeErr);
            activeCompletions = null;
        } else grain.清空();
        resolveIdle();
    };

    const bundle = () => {
        const packed = grain.合包();
        if (!packed) return null;
        let allowRetry = true;
        let completions = null;
        for (const item of packed.items) {
            allowRetry = allowRetry && item.allowRetry;
            if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
        }
        return { chunk: packed.chunk, allowRetry, completions };
    };

    const 等待可用写入器 = async () => {
        let writer = 获取写入器();
        if (writer) return writer;
        const connectionTask = 获取连接任务?.();
        if (connectionTask) await connectionTask;
        return 获取写入器();
    };

    const drain = async () => {
        if (draining || closed) return;
        draining = true;
        try {
            for (; ;) {
                if (closed) break;
                const item = bundle();
                if (!item) break;
                const completions = item.completions || null;
                activeCompletions = completions;
                try {
                    let writer = await 等待可用写入器();
                    if (closed) break;
                    if (!writer) throw new Error(`${名称}: remote writer unavailable`);
                    try {
                        await writer.write(item.chunk);
                    } catch (err) {
                        释放写入器?.();
                        if (closed) break;
                        if (!item.allowRetry || typeof 重试连接 !== 'function') throw err;
                        await 重试连接();
                        if (closed) break;
                        writer = 获取写入器();
                        if (!writer) throw err;
                        await writer.write(item.chunk);
                    }
                    settleCompletions(completions);
                } catch (err) {
                    settleCompletions(completions, err);
                    throw err;
                } finally {
                    if (activeCompletions === completions) activeCompletions = null;
                }
            }
        } catch (err) {
            closed = true;
            clear(err);
            log(`[${名称}] 写入失败: ${err?.message || err}`);
            try { 关闭连接?.(err) } catch (_) { }
        } finally {
            draining = false;
            if (!closed && !grain.为空) drain();
            else resolveIdle();
        }
    };

    const enqueue = (data, allowRetry = true, waitForFlush = false) => {
        if (closed) return false;
        // 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
        if (!获取写入器() && !获取连接任务?.()) return false;
        const chunk = 数据转Uint8Array(data);
        if (!chunk.byteLength) return true;
        const nextBytes = grain.字节数 + chunk.byteLength;
        const nextItems = grain.条目数 + 1;
        if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
            closed = true;
            const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
            clear(err);
            log(`[${名称}] 队列超限，关闭连接`);
            try { 关闭连接?.(err) } catch (_) { }
            throw err;
        }
        let completionPromise = null;
        let completions = null;
        if (waitForFlush) {
            completions = [];
            completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
        }
        grain.收纳({ chunk, allowRetry, completions });
        if (!draining) drain();
        return waitForFlush ? completionPromise.then(() => true) : true;
    };

    return {
        写入(data, allowRetry = true) {
            return enqueue(data, allowRetry, false);
        },
        写入并等待(data, allowRetry = true) {
            return enqueue(data, allowRetry, true);
        },
        async 等待空() {
            if (!grain.字节数 && !draining) return;
            await new Promise(resolve => idleResolvers.push(resolve));
        },
        清空() {
            closed = true;
            clear();
        }
    };
}

function 创建下行Grain发送器(webSocket, headerData = null, isActive = null) {
    const packetCap = 下行Grain包字节;
    const tailBytes = 下行Grain尾部阈值;
    const grain = 创建Grain收纳器(packetCap, true);
    let header = typeof headerData === 'function' ? null : headerData;
    const 获取响应头 = typeof headerData === 'function' ? headerData : () => {
        const value = header;
        header = null;
        return value;
    };
    let flushTimer = null;
    let generation = 0;
    let scheduledGeneration = 0;
    let waitRounds = 0;
    let flushPromise = null;
    let directSendPromise = null;
    let 强制排空 = false;
    let 停止已开始 = false;
    let 活动发送数 = 0;
    let 活动直发数 = 0;
    let 活动发送错误 = null;
    let 活动发送等待者 = [];
    const 等待活动发送完成 = () => {
        if (!活动发送数 && !活动直发数) return Promise.resolve();
        return new Promise(resolve => 活动发送等待者.push(resolve));
    };
    const 标记发送完成 = () => {
        if (活动发送数 || 活动直发数 || !活动发送等待者.length) return;
        const resolvers = 活动发送等待者;
        活动发送等待者 = [];
        for (const resolve of resolvers) resolve();
    };
    const 检查活动发送错误 = () => {
        if (!活动发送错误) return;
        const err = 活动发送错误;
        grain.清空();
        throw err;
    };
    const 当前发送器有效 = () => 强制排空 || !isActive || isActive();
    const 关闭活动连接 = () => {
        if (当前发送器有效()) closeSocketQuietly(webSocket);
    };

    const 发送原始块 = async (chunk) => {
        if (!当前发送器有效()) return;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) throw new Error('ws.readyState is not open');
        chunk = 附加响应头(chunk);
        await WebSocket发送并等待(webSocket, chunk);
    };

    const 串行发送原始块 = async (chunk) => {
        while (directSendPromise) await directSendPromise;
        const sendTask = 发送原始块(chunk);
        directSendPromise = sendTask;
        try { await sendTask }
        finally {
            if (directSendPromise === sendTask) directSendPromise = null;
        }
    };

    const 附加响应头 = (chunk) => {
        const responseHeader = 获取响应头();
        if (!responseHeader) return chunk;
        const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
        merged.set(responseHeader, 0);
        merged.set(chunk, responseHeader.length);
        return merged;
    };

    const flush = async () => {
        while (flushPromise) await flushPromise;
        if (flushTimer) clearTimeout(flushTimer);
        flushTimer = null;
        waitRounds = 0;
        if (!当前发送器有效()) {
            grain.清空();
            return;
        }
        const 发送任务 = (async () => {
            for (; ;) {
                if (!当前发送器有效()) {
                    grain.清空();
                    break;
                }
                const packed = grain.合包();
                if (!packed) break;
                await 串行发送原始块(packed.chunk);
            }
        })();
        flushPromise = 发送任务.catch(err => {
            活动发送错误 ||= err;
            throw err;
        }).finally(() => { flushPromise = null });
        return flushPromise;
    };

    const scheduleFlush = () => {
        if (!当前发送器有效()) {
            grain.清空();
            return;
        }
        if (grain.为空 || flushTimer) return;
        if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
            flush().catch(关闭活动连接);
            return;
        }
        flushTimer = setTimeout(() => {
            flushTimer = null;
            if (!当前发送器有效()) {
                grain.清空();
                return;
            }
            if (grain.为空) return;
            if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
                flush().catch(关闭活动连接);
                return;
            }
            if (waitRounds < 下行Grain最大等待轮次 && (generation !== scheduledGeneration || grain.字节数 < 下行Grain低水位字节)) {
                waitRounds++;
                scheduledGeneration = generation;
                scheduleFlush();
                return;
            }
            flush().catch(关闭活动连接);
        }, 1);
    };

    return {
        async 直接发送(data) {
            if (停止已开始 || !当前发送器有效()) return;
            活动直发数++;
            try {
                const chunk = 数据转Uint8Array(data);
                if (!chunk.byteLength) return;
                await 串行发送原始块(chunk);
            } catch (err) {
                活动发送错误 ||= err;
                throw err;
            } finally {
                活动直发数--;
                标记发送完成();
            }
        },
        async 发送(data) {
            if (停止已开始 || !当前发送器有效()) return;
            活动发送数++;
            try {
                const chunk = 数据转Uint8Array(data);
                if (!chunk.byteLength) return;
                let offset = 0;
                const totalBytes = chunk.byteLength;
                while (offset < totalBytes) {
                    const remainingBytes = totalBytes - offset;
                    if (grain.为空 && remainingBytes >= packetCap) {
                        const sendBytes = Math.min(packetCap, remainingBytes);
                        const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
                        await 串行发送原始块(view);
                        offset += sendBytes;
                        continue;
                    }
                    const copyBytes = Math.min(packetCap - grain.字节数, totalBytes - offset);
                    if (!copyBytes) {
                        await flush();
                        continue;
                    }
                    grain.收纳({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
                    offset += copyBytes;
                    generation++;
                    if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) await flush();
                    else scheduleFlush();
                }
            } catch (err) {
                活动发送错误 ||= err;
                throw err;
            } finally {
                活动发送数--;
                标记发送完成();
            }
        },
        flush,
        async 停止并刷新() {
            if (停止已开始) {
                await 等待活动发送完成();
                while (directSendPromise) await directSendPromise;
                检查活动发送错误();
                await flush();
                return;
            }
            停止已开始 = true;
            强制排空 = true;
            if (flushTimer) clearTimeout(flushTimer);
            flushTimer = null;
            await 等待活动发送完成();
            while (directSendPromise) await directSendPromise;
            检查活动发送错误();
            await flush();
        }
    };
}

function 失效TCP连接世代(remoteConnWrapper) {
    if (!remoteConnWrapper) return;
    remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
    const socket = remoteConnWrapper.socket;
    remoteConnWrapper.socket = null;
    remoteConnWrapper.downlinkController = null;
    remoteConnWrapper.downlinkDrain = Promise.resolve();
    try { socket?.close?.() } catch (e) { }
}

function 开始TCP连接世代(remoteConnWrapper) {
    if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
    const generation = ++remoteConnWrapper.generation;
    const previousSocket = remoteConnWrapper.socket;
    remoteConnWrapper.socket = null;
    const previousDownlink = remoteConnWrapper.downlinkController;
    remoteConnWrapper.downlinkController = null;
    const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
    let currentDrain;
    try { currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve() }
    catch (error) { currentDrain = Promise.reject(error) }
    const downlinkDrain = Promise.all([previousDrain, currentDrain]);
    downlinkDrain.catch(() => { });
    remoteConnWrapper.downlinkDrain = downlinkDrain;
    try { previousSocket?.close?.() } catch (e) { }
    return { generation, downlinkDrain };
}

async function forwardataTCP(host, portNum, rawData, ws, remoteConnWrapper, customProxyIP) {
    let 已通过代理发送首包 = false;
    const 回退地址列表 = String(customProxyIP || proxyIP || '').split(',').map(s => s.trim()).filter(s => s && !s.startsWith('.'));
    let 回退索引 = 0;
    if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

    const 安装当前连接 = async (socket, generation, downlinkDrain, retryFunc = null) => {
        try { await downlinkDrain } catch (e) {
            if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
            try { socket?.close?.() } catch (_) { }
            if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
            throw e;
        }
        if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
        const 连接仍有效 = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
        if (remoteConnWrapper.generation !== generation || ws.readyState !== WS_READY_STATE_OPEN) {
            try { socket?.close?.() } catch (e) { }
            if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
            throw new Error('connection superseded or client closed');
        }
        remoteConnWrapper.socket = socket;
        connectStreams(socket, ws, null, retryFunc, 连接仍有效, remoteConnWrapper).catch(err => {
            if (!连接仍有效()) return;
            log(`[TCP下行] 处理失败: ${err?.message || err}`);
            try { socket?.close?.() } catch (e) { }
            closeSocketQuietly(ws);
        });
        return true;
    };

    async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
        await Promise.race([
            remoteSock.opened,
            new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
        ]);
    }

    async function 打开TCP连接(address, port) {
        const remoteSock = connect({ hostname: address, port });
        try {
            await 等待连接建立(remoteSock);
            return remoteSock;
        } catch (err) {
            try { remoteSock?.close?.() } catch (e) { }
            throw err;
        }
    }

    async function 并发打开候选连接(候选列表) {
        if (候选列表.length === 1) {
            const 候选 = 候选列表[0];
            return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
        }
        const attempts = 候选列表.map(候选 => 打开TCP连接(候选.hostname, 候选.port).then(socket => ({ socket, candidate: 候选 })));
        let winner = null;
        try {
            winner = await Promise.any(attempts);
            return winner;
        } finally {
            if (winner) {
                for (const attempt of attempts) {
                    attempt.then(({ socket }) => {
                        if (socket !== winner.socket) {
                            try { socket?.close?.() } catch (e) { }
                        }
                    }).catch(() => { });
                }
            }
        }
    }

    async function 构建预加载竞速候选列表(address, port) {
        if (!预加载竞速拨号 || isIPHostname(address)) return null;
        log(`[TCP直连] 预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
        const [aRecords, aaaaRecords] = await Promise.all([
            DoH查询(address, 'A'),
            DoH查询(address, 'AAAA')
        ]);
        const ipv4List = [...new Set(aRecords.flatMap(r => {
            const data = r.data;
            return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
        }))];
        const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
            const data = r.data;
            return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
        }))];
        const 拨号上限 = Math.max(1, TCP并发拨号数 | 0);
        const ipList = ipv4List.length >= 拨号上限
            ? ipv4List.slice(0, 拨号上限)
            : ipv4List.concat(ipv6List.slice(0, 拨号上限 - ipv4List.length));
        if (ipList.length === 0) {
            log(`[TCP直连] ${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
            return null;
        }
        log(`[TCP直连] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，竞速拨号 ${ipList.length}/${拨号上限}: ${ipList.join(', ')}`);
        return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
    }

    async function 写入首包(remoteSock, data) {
        if (有效数据长度(data) <= 0) return;
        const writer = remoteSock.writable.getWriter();
        try { await writer.write(数据转Uint8Array(data)) }
        finally { try { writer.releaseLock() } catch (e) { } }
    }

    async function connectDirect(address, port, data = null, 启用预加载 = false, 并发数 = TCP并发拨号数) {
        const 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;
        const 候选列表 = 预加载候选列表 || Array.from({ length: Math.max(1, Number(并发数) || 1) }, (_, attempt) => ({ hostname: address, port, attempt }));
        log(预加载候选列表
            ? `[TCP直连] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
            : `[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
        let socket = null;
        try {
            const 连接结果 = await 并发打开候选连接(候选列表);
            socket = 连接结果.socket;
            if (预加载候选列表) {
                const winner = 连接结果.candidate;
                log(`[TCP直连] 预加载竞速结果: ${winner.hostname}:${winner.port} 胜出`);
            }
            await 写入首包(socket, data);
            return socket;
        } catch (err) {
            try { socket?.close?.() } catch (e) { }
            if (预加载候选列表) log(`[TCP直连] 预加载竞速失败: ${err.message || err}`);
            throw err;
        }
    }

    async function connecttoPry(允许发送首包 = true) {
        if (remoteConnWrapper.connectingPromise) {
            await remoteConnWrapper.connectingPromise;
            return;
        }
        const { generation: 当前连接世代, downlinkDrain } = 开始TCP连接世代(remoteConnWrapper);

        const 本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
        const 本次首包数据 = 本次发送首包 ? rawData : null;

        const 当前连接任务 = (async () => {
            let newSocket = null, lastError = null;
            for (let i = 0; i < 回退地址列表.length && !newSocket; i++) {
                const 候选地址 = 回退地址列表[(回退索引 + i) % 回退地址列表.length];
                try {
                    const proxyConfig = parsePryAddress(候选地址) || { type: 'direct', host: 候选地址, port: 443 };
                    log(`[回退连接] 代理到: ${host}:${portNum} via ${proxyConfig.host}:${proxyConfig.port}`);
                    newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, 本次首包数据, false, 反代并发拨号数);
                    回退索引 = (回退索引 + i) % 回退地址列表.length;
                } catch (err) {
                    lastError = err;
                    log(`[回退连接] 候选失败: ${候选地址} - ${err.message}`);
                }
            }
            try {
                if (!newSocket) throw lastError || new Error('所有回退地址均连接失败');
                await 安装当前连接(newSocket, 当前连接世代, downlinkDrain);
                if (本次发送首包) 已通过代理发送首包 = true;
            } catch (err) {
                try { newSocket?.close?.() } catch (e) { }
                if (remoteConnWrapper.generation === 当前连接世代) {
                    remoteConnWrapper.socket = null;
                    closeSocketQuietly(ws);
                    throw err;
                }
            }
        })();

        remoteConnWrapper.connectingPromise = 当前连接任务;
        try {
            await 当前连接任务;
        } finally {
            if (remoteConnWrapper.connectingPromise === 当前连接任务) {
                remoteConnWrapper.connectingPromise = null;
            }
        }
    }
    remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

    let 直连世代 = remoteConnWrapper.generation;
    try {
        log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
        const 世代连接 = 开始TCP连接世代(remoteConnWrapper);
        直连世代 = 世代连接.generation;
        const initialSocket = await connectDirect(host, portNum, rawData, true);
        await 安装当前连接(initialSocket, 直连世代, 世代连接.downlinkDrain, async () => {
            if (remoteConnWrapper.generation !== 直连世代 || remoteConnWrapper.socket !== initialSocket) return;
            await connecttoPry();
        });
    } catch (err) {
        log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
        if (remoteConnWrapper.generation !== 直连世代) throw err;
        if (ws.readyState !== WS_READY_STATE_OPEN) throw err;
        await connecttoPry();
    }
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
    let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
    const BYOB单次读取上限 = 64 * 1024;
    const 当前连接仍有效 = () => !isCurrentSocket || isCurrentSocket();
    const 下行发送器 = 创建下行Grain发送器(webSocket, header, 当前连接仍有效);
    header = null;
    const 下行控制器 = { 停止并刷新: () => 下行发送器.停止并刷新() };
    if (remoteConnWrapper) remoteConnWrapper.downlinkController = 下行控制器;
    try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

    try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
    catch (e) { reader = remoteSocket.readable.getReader() }

    try {
        if (!useBYOB) {
            while (true) {
                const { done, value } = await reader.read();
                if (!当前连接仍有效()) break;
                if (done) break;
                if (!value || value.byteLength === 0) continue;
                hasData = true;
                if (value.byteLength >= 下行Grain包字节) {
                    await 下行发送器.flush();
                    await 下行发送器.直接发送(value);
                } else {
                    await 下行发送器.发送(value);
                }
            }
        } else {
            let readBuffer = new ArrayBuffer(BYOB单次读取上限);
            while (true) {
                const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
                if (!当前连接仍有效()) break;
                if (done) break;
                if (!value || value.byteLength === 0) continue;
                hasData = true;
                if (value.byteLength >= 下行Grain包字节) {
                    await 下行发送器.flush();
                    await 下行发送器.直接发送(value);
                    readBuffer = new ArrayBuffer(BYOB单次读取上限);
                } else {
                    await 下行发送器.发送(value.slice());
                    readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
                }
            }
        }
        if (当前连接仍有效()) await 下行发送器.flush();
    } catch (err) { readError = err }
    finally {
        if (当前连接仍有效() && webSocket.readyState === WS_READY_STATE_OPEN) {
            try { await 下行发送器.停止并刷新() } catch (err) { readError ||= err }
        }
        if (remoteConnWrapper?.downlinkController === 下行控制器) remoteConnWrapper.downlinkController = null;
        try { await reader.cancel() } catch (e) { }
        try { reader.releaseLock() } catch (e) { }
        try { remoteSocket.close() } catch (e) { }
    }
    if (!hasData && retryFunc && webSocket.readyState === WS_READY_STATE_OPEN && 当前连接仍有效()) {
        try {
            await retryFunc();
            return;
        } catch (err) {
            readError ||= err;
        }
    }
    if (!当前连接仍有效()) return;
    if (readError) log(`[TCP下行] 读取失败: ${readError?.message || readError}`);
    closeSocketQuietly(webSocket);
}

export default {
    async fetch(request, env) {
        try {
            调试日志打印 = ['1', 'true'].includes(env?.DEBUG) || 调试日志打印;
            预加载竞速拨号 = ['1', 'true'].includes(env?.PRELOAD_RACE_DIAL) || 预加载竞速拨号;
            TCP并发拨号数 = Math.max(1, Number(env?.TCP_CONCURRENT_DIAL) || TCP并发拨号数);
            反代并发拨号数 = Math.max(1, Number(env?.PROXY_CONCURRENT_DIAL) || 反代并发拨号数);
            连接超时毫秒 = Math.max(500, Number(env?.CONNECT_TIMEOUT_MS) || 连接超时毫秒);
            if (request.headers.get('Upgrade') === 'websocket') {
                const url = new URL(request.url);
                let wsPathProxyIP = null;
                if (url.pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(url.pathname.substring(9)).trim();
                    } catch (e) {}
                }
                const 配置回退地址 = proxyIP.includes('{colo}') ? proxyIP.replace(/\{colo\}/g, String(request.cf?.colo || '').toLowerCase()) : proxyIP;
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip') || 配置回退地址;
                return await handleTroRequest(request, customProxyIP);
            }
            if (request.method === 'GET' && new URL(request.url).pathname === '/') {
                return new Response('Hello trojan!\n\nUsage: wss://<host>[/<path>][?proxyip=<fallback-address>]\n');
            }
            return new Response('Not Found', { status: 404 });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
