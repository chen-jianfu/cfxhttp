import {
    connect
}
from 'cloudflare:sockets';

// ============================================================================
// 全局配置与常量
// ============================================================================
const DEFAULT_UUID = '96c50e3a-5b87-49dd-bd20-03c7f2735e40';
const CF_FALLBACK_IPS = ['ProxyIP.US.CMLiussss.net'];

const PROTO_VER = 0;
const TYPE_TCP = 1;
const ADDR_V4 = 1;
const ADDR_DNS = 2;
const ADDR_V6 = 3;

// ============================================================================
const NGINX_HTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;

// ============================================================================
// 全局对象复用 (微秒级优化：消除冷启动后的对象创建开销与 GC 压力)
// ============================================================================
const TEXT_DECODER = new TextDecoder();
let CACHED_UUID = '';
let AUTH_CHUNKS = new Uint8Array(16);

// 极速零分配 UUID 校验 (循环展开)
function checkAuth(buffer, offset) {
    return buffer[offset] === AUTH_CHUNKS[0] &&
    buffer[offset + 1] === AUTH_CHUNKS[1] &&
    buffer[offset + 2] === AUTH_CHUNKS[2] &&
    buffer[offset + 3] === AUTH_CHUNKS[3] &&
    buffer[offset + 4] === AUTH_CHUNKS[4] &&
    buffer[offset + 5] === AUTH_CHUNKS[5] &&
    buffer[offset + 6] === AUTH_CHUNKS[6] &&
    buffer[offset + 7] === AUTH_CHUNKS[7] &&
    buffer[offset + 8] === AUTH_CHUNKS[8] &&
    buffer[offset + 9] === AUTH_CHUNKS[9] &&
    buffer[offset + 10] === AUTH_CHUNKS[10] &&
    buffer[offset + 11] === AUTH_CHUNKS[11] &&
    buffer[offset + 12] === AUTH_CHUNKS[12] &&
    buffer[offset + 13] === AUTH_CHUNKS[13] &&
    buffer[offset + 14] === AUTH_CHUNKS[14] &&
    buffer[offset + 15] === AUTH_CHUNKS[15];
}

function isCFError(err) {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') ||
    msg.includes('cannot connect') ||
    msg.includes('cloudflare');
}

// ============================================================================
// VLESS 协议头解析器 (带自动扩容安全机制的极速版)
// ============================================================================
async function resolveHeader(streamReader) {
    let buffer = new Uint8Array(4096);
    let offset = 0;

    const requireBytes = async(length) => {
        while (offset < length) {
            const {
                value,
                done
            } = await streamReader.read();
            if (done)
                return false;

            // 自动扩容防御机制，防止大包导致越界 500 错误
            if (offset + value.length > buffer.length) {
                const newSize = Math.max(buffer.length * 2, offset + value.length);
                const newBuffer = new Uint8Array(newSize);
                newBuffer.set(buffer);
                buffer = newBuffer;
            }

            buffer.set(value, offset);
            offset += value.length;
        }
        return true;
    };

    if (!(await requireBytes(18)))
        return null;
    if (buffer[0] !== PROTO_VER)
        return {
            error: 'Err:V'
        };
    if (!checkAuth(buffer, 1))
        return {
            error: 'Err:A'
        };

    const metaLen = buffer[17];
    const addrTypeIdx = 18 + metaLen + 2;

    if (!(await requireBytes(addrTypeIdx + 1)))
        return null;

    const action = buffer[18 + metaLen];
    if (action !== TYPE_TCP)
        return {
            error: `Err:C-${action}`
        };

    const portIdx = 18 + metaLen + 1;
    const port = (buffer[portIdx] << 8) | buffer[portIdx + 1];
    const addrType = buffer[portIdx + 2];
    const addrStart = portIdx + 3;

    let targetAddr = '';
    let payloadStart = 0;

    if (addrType === ADDR_V4) {
        payloadStart = addrStart + 4;
        if (!(await requireBytes(payloadStart)))
            return null;
        targetAddr = `${buffer[addrStart]}.${buffer[addrStart+1]}.${buffer[addrStart+2]}.${buffer[addrStart+3]}`;

    } else if (addrType === ADDR_DNS) {
        if (!(await requireBytes(addrStart + 1)))
            return null;
        const dnsLen = buffer[addrStart];
        payloadStart = addrStart + 1 + dnsLen;
        if (!(await requireBytes(payloadStart)))
            return null;
        targetAddr = TEXT_DECODER.decode(buffer.subarray(addrStart + 1, payloadStart));

    } else if (addrType === ADDR_V6) {
        payloadStart = addrStart + 16;
        if (!(await requireBytes(payloadStart)))
            return null;
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(((buffer[addrStart + i] << 8) | buffer[addrStart + i + 1]).toString(16));
        }
        targetAddr = `[${parts.join(':')}]`;
    } else {
        return {
            error: `Err:T-${addrType}`
        };
    }

    const initialData = offset > payloadStart ? buffer.slice(payloadStart, offset) : new Uint8Array(0);
    return {
        targetAddr,
        port,
        initialData,
        ver: buffer[0]
    };
}

// ============================================================================
// 核心 Worker 处理器
// ============================================================================
export default {
    async fetch(request, env, ctx) {
        const _KEY = env.UUID || DEFAULT_UUID;

        // 动态缓存 UUID 转换，避免热请求重复计算
        if (_KEY !== CACHED_UUID) {
            CACHED_UUID = _KEY;
            const cleanHex = _KEY.replace(/-/g, '');
            for (let i = 0; i < 16; i++) {
                AUTH_CHUNKS[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
            }
        }

        // 处理 GET 请求 (伪装墙与订阅下发)
        if (request.method === 'GET') {
            const url = new URL(request.url);
            if (url.pathname.includes(_KEY) || url.search.includes(_KEY)) {
                return new Response(buildSchema(url, _KEY), {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
            }
            return new Response(NGINX_HTML, {
                status: 200,
                headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Server': 'nginx'
                }
            });
        }

        if (request.method !== 'POST')
            return new Response('Forbidden', {
                status: 403
            });

        const ingressReader = request.body.getReader();

        try {
            const headerInfo = await resolveHeader(ingressReader);

            if (!headerInfo) {
                ingressReader.releaseLock();
                return new Response('Short Frame', {
                    status: 400
                });
            }
            if (headerInfo.error) {
                ingressReader.releaseLock();
                return new Response(headerInfo.error, {
                    status: 400
                });
            }

            let egressSocket = null;
            let connectionSuccess = false;
            const fallbackIPs = env.PROXY ? [env.PROXY, ...CF_FALLBACK_IPS] : CF_FALLBACK_IPS;
            const attempts = [null, ...fallbackIPs];

            // 智能回退防阻断机制
            for (let i = 0; i < attempts.length; i++) {
                try {
                    const connectHost = attempts[i] || headerInfo.targetAddr;
                    egressSocket = connect({
                        hostname: connectHost,
                        port: headerInfo.port
                    });
                    await egressSocket.opened;
                    connectionSuccess = true;
                    break;
                } catch (err) {
                    try {
                        egressSocket?.close();
                    } catch {}
                    if (!isCFError(err) || i === attempts.length - 1) {
                        ingressReader.releaseLock();
                        return new Response(`Connection Failed`, {
                            status: 502
                        });
                    }
                }
            }

            if (!connectionSuccess) {
                ingressReader.releaseLock();
                return new Response('Failed', {
                    status: 502
                });
            }

            // ==========================================================
            // ==========================================================
            const egressWriter = egressSocket.writable.getWriter();
            ctx.waitUntil((async() => {
                    try {
                        // 1. 吐出首帧
                        if (headerInfo.initialData.length > 0) {
                            await egressWriter.write(headerInfo.initialData);
                        }

                        // 2. 极简高效泵送
                        while (true) {
                            const {
                                done,
                                value
                            } = await ingressReader.read();
                            if (done)
                                break;
                            await egressWriter.write(value);
                        }
                    } catch (e) {
                        // 忽略传输过程中的网络断开错误
                    } finally {
                        // 3. 双向安全释放：确保两端彻底闭环
                        try {
                            ingressReader.cancel().catch(() => {});
                        } catch (e) {}
                        // 核心：防止前端连接半悬挂
                        try {
                            egressWriter.releaseLock();
                        } catch (e) {}
                        try {
                            egressSocket.close();
                        } catch (e) {}
                    }
                })());

            // ==========================================================
            // 🔵 下行流量 (Server -> Client) : 对称的背压感知异步泵
            // ==========================================================
            const feedbackHead = new Uint8Array([headerInfo.ver, 0]);
            // 创建一个中转流，readable 给 Response 返回给客户端，writable 留给我们用 JS 写入
            const {
                readable: outputStream,
                writable: clientWritable
            } = new TransformStream();

            ctx.waitUntil((async() => {
                    // 获取服务端的读取器和客户端的写入器
                    const serverReader = egressSocket.readable.getReader();
                    const clientWriter = clientWritable.getWriter();

                    try {
                        // 1. 先把 VLESS 响应头塞给客户端
                        await clientWriter.write(feedbackHead);

                        // 2. 开始 JS 显式循环搬运（远端服务器 -> 客户端）
                        while (true) {
                            const {
                                done,
                                value
                            } = await serverReader.read();
                            if (done)
                                break;

                            // 控速挂起，等待客户端接收通道准备就绪
                            await clientWriter.ready;

                            // 异步写入给客户端，通过 catch 兜住客户端可能随时断开的异常
                            clientWriter.write(value).catch(() => {});
                        }
                    } catch (e) {
                        // 忽略传输过程中的网络断开错误
                    } finally {
                        // 双向安全释放：确保远端读取停止，且向客户端的写入流正常结束
                        try {
                            serverReader.cancel().catch(() => {});
                        } catch {}
                        // 注意这里：直接 close() writer 可以让 HTTP 响应正常结束，告诉客户端下载完毕
                        try {
                            clientWriter.close();
                        } catch {}
                    }
                })());

            // 返回 outputStream，里面是我们用 JS 循环一点点 write 进去的数据
            return new Response(outputStream, {
                status: 200,
                headers: {
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/octet-stream',
                    'X-Relay-Status': 'Active'
                }
            });

        } catch (err) {
            try {
                ingressReader.releaseLock();
            } catch {}
            return new Response('Internal Pipeline Error', {
                status: 500
            });
        }
    }
};

function buildSchema(url, key) {
    const sHost = url.hostname;
    const sPath = url.pathname.endsWith('/') ? url.pathname : `${url.pathname}/`;
    return JSON.stringify({
        "service": "Data-Forwarder",
        "engine": {
            "level": "stable"
        },
        "in": [{
                "port": 1080,
                "type": "bridge"
            }
        ],
        "out": [{
                "type": "tunnel",
                "params": {
                    "endpoint": sHost,
                    "port": 443,
                    "auth": [{
                            "token": key
                        }
                    ]
                },
                "transport": {
                    "proto": "xhttp",
                    "options": {
                        "mode": "stream",
                        "host": sHost,
                        "path": sPath
                    },
                    "tls": {
                        "sni": sHost
                    }
                }
            }
        ]
    }, null, 2);
}
