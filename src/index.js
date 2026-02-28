import { connect } from 'cloudflare:sockets'

// -----------------------------------------------------------------------------
// 全局参数配置
// -----------------------------------------------------------------------------
const AUTH_KEY = '96c50e3a-5b87-49dd-bd20-03c7f2735e40'
// 备用中继节点地址 (硬编码的兜底回退 IP)
const CF_FALLBACK_IPS = ['13.230.34.30']

// -----------------------------------------------------------------------------
// 数据处理与校验工具
// -----------------------------------------------------------------------------
const AUTH_CHUNKS = new Uint8Array(16)
for (let i = 0; i < 16; i++) {
    AUTH_CHUNKS[i] = parseInt(AUTH_KEY.replace(/-/g, '').substr(i * 2, 2), 16)
}

function mergeBuffer(a, b) {
    const c = new Uint8Array(a.length + b.length)
    c.set(a)
    c.set(b, a.length)
    return c
}

function checkAuth(id) {
    for (let i = 0; i < 16; i++) {
        if (id[i] !== AUTH_CHUNKS[i]) return false
    }
    return true
}


function isCFError(err) {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') || 
           msg.includes('cannot connect') || 
           msg.includes('cloudflare');
}

// -----------------------------------------------------------------------------
// 协议头解析器 (VLESS)
// -----------------------------------------------------------------------------
const PROTO_VER = 0
const TYPE_TCP = 1
const ADDR_V4 = 1
const ADDR_DNS = 2
const ADDR_V6 = 3

// 真正高效的头部解析器 (零拷贝理念)
async function resolveHeader(streamReader) {
    const buffer = new Uint8Array(2048); // 预分配一个足够大的缓冲区
    let offset = 0;

    // 辅助函数：确保缓冲区里有指定的字节数
    const requireBytes = async (length) => {
        while (offset < length) {
            const { value, done } = await streamReader.read();
            if (done) return false; // 流提前结束
            buffer.set(value, offset);
            offset += value.length;
        }
        return true;
    };

    // 1. 读取基础头部 (至少 18 字节: 1(ver) + 16(uuid) + 1(meta_len))
    if (!(await requireBytes(18))) return null;
    
    if (buffer[0] !== PROTO_VER) return { error: 'Err:V' };
    if (!checkAuth(buffer.subarray(1, 17))) return { error: 'Err:A' };

    const metaLen = buffer[17];
    
    // 2. 读取完整的 Meta + Action + Port + AddrType
    const addrTypeIdx = 18 + metaLen + 2; 
    if (!(await requireBytes(addrTypeIdx + 1))) return null;

    const action = buffer[18 + metaLen];
    if (action !== TYPE_TCP) return { error: `Err:C-${action}` };

    const portIdx = 18 + metaLen + 1;
    const port = (buffer[portIdx] << 8) | buffer[portIdx + 1];
    const addrType = buffer[portIdx + 2];
    const addrStart = portIdx + 3;

    let targetAddr = '';
    let payloadStart = 0;

    // 3. 根据地址类型读取地址
    if (addrType === ADDR_V4) {
        payloadStart = addrStart + 4;
        if (!(await requireBytes(payloadStart))) return null;
        targetAddr = `${buffer[addrStart]}.${buffer[addrStart+1]}.${buffer[addrStart+2]}.${buffer[addrStart+3]}`;
        
    } else if (addrType === ADDR_DNS) {
        if (!(await requireBytes(addrStart + 1))) return null;
        const dnsLen = buffer[addrStart];
        payloadStart = addrStart + 1 + dnsLen;
        if (!(await requireBytes(payloadStart))) return null;
        targetAddr = new TextDecoder().decode(buffer.subarray(addrStart + 1, payloadStart));
        
    } else if (addrType === ADDR_V6) {
        payloadStart = addrStart + 16;
        if (!(await requireBytes(payloadStart))) return null;
        // 使用优化后的 IPv6 位运算拼接
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(((buffer[addrStart + i] << 8) | buffer[addrStart + i + 1]).toString(16));
        }
        targetAddr = `[${parts.join(':')}]`;
        
    } else {
        return { error: `Err:T-${addrType}` };
    }

    // 将多读出来的数据（首帧 Payload）作为 initialData 返回
    const initialData = offset > payloadStart ? buffer.slice(payloadStart, offset) : new Uint8Array(0);
    
    return { targetAddr, port, initialData, ver: buffer[0] };
}

// -----------------------------------------------------------------------------
// 核心中继控制器
// -----------------------------------------------------------------------------
export default {
    async fetch(request, env, ctx) {
        const _KEY = env.UUID || AUTH_KEY
        
        if (request.method === 'GET') {
            const url = new URL(request.url)
            if (url.pathname.includes(_KEY) || url.search.includes(_KEY)) {
                return new Response(buildSchema(url, _KEY), { headers: { 'Content-Type': 'application/json' } })
            }
            return new Response('Relay Service Active', { status: 200 })
        }

        if (request.method !== 'POST') return new Response('Forbidden', { status: 403 })

        try {
            const ingressReader = request.body.getReader()
            const headerInfo = await resolveHeader(ingressReader)
            
            if (!headerInfo) return new Response('Short Frame', { status: 400 })
            if (headerInfo.error) {
                ingressReader.releaseLock() 
                return new Response(headerInfo.error, { status: 400 })
            }

            let egressSocket = null;
            let connectionSuccess = false;

            // 构建尝试列表：[null (代表原目标), ...环境配置节点(如果有), ...硬编码兜底节点]
            const fallbackIPs = env.PROXY ? [env.PROXY, ...CF_FALLBACK_IPS] : CF_FALLBACK_IPS;
            const attempts = [null, ...fallbackIPs];

            // 循环尝试连接机制
            for (let i = 0; i < attempts.length; i++) {
                try {
                    const connectHost = attempts[i] || headerInfo.targetAddr;
                    egressSocket = connect({ hostname: connectHost, port: headerInfo.port });
                    
                    // 等待连接真正建立
                    await egressSocket.opened;
                    connectionSuccess = true;
                    break; // 连接成功，跳出循环

                } catch (err) {
                    // 连接失败，清理无效的 Socket
                    try { egressSocket?.close(); } catch {}

                    // 如果不是 CF 封锁导致的错误，或者已经是最后一次尝试，则终止并抛出
                    if (!isCFError(err) || i === attempts.length - 1) {
                        ingressReader.releaseLock();
                        return new Response(`Connection Failed: ${err?.message || 'Unknown error'}`, { status: 502 });
                    }
                    // 如果是 CF 错误且还有剩余的 fallback IP，循环将继续 (重试)
                }
            }

            if (!connectionSuccess || !egressSocket) {
                ingressReader.releaseLock();
                return new Response('All connection attempts failed', { status: 502 });
            }

            const egressWriter = egressSocket.writable.getWriter()
            
            // 上行流量中继 (Ingress -> Egress)
            ctx.waitUntil((async () => {
                try {
                    if (headerInfo.initialData.length > 0) await egressWriter.write(headerInfo.initialData)
                    while (true) {
                        const { done, value } = await ingressReader.read()
                        if (done) break
                        await egressWriter.write(value)
                    }
                } catch (e) {} finally {
                    egressWriter.close()
                }
            })())

            // 下行流量中继 (Egress -> Ingress)
            const feedbackHead = new Uint8Array([headerInfo.ver, 0])
            const { readable: outputStream, writable: internalLink } = new TransformStream()
            const feedbackWriter = internalLink.getWriter()
            
            ctx.waitUntil((async () => {
                try {
                    await feedbackWriter.write(feedbackHead)
                    feedbackWriter.releaseLock() 
                    await egressSocket.readable.pipeTo(internalLink) 
                } catch (e) {}
            })())

            return new Response(outputStream, {
                status: 200,
                headers: { 
                    'Connection': 'keep-alive', 
                    'Content-Type': 'application/octet-stream', 
                    'X-Relay-Status': 'Active' 
                }
            })

        } catch (err) {
            return new Response('Internal Pipeline Error', { status: 500 })
        }
    }
}

function buildSchema(url, key) {
    const sHost = url.hostname
    const sPath = url.pathname.endsWith('/') ? url.pathname : `${url.pathname}/`
    return JSON.stringify({
        "service": "Data-Forwarder",
        "engine": { "level": "stable" },
        "in": [{ "port": 1080, "type": "bridge" }],
        "out": [{
            "type": "tunnel",
            "params": { "endpoint": sHost, "port": 443, "auth": [{ "token": key }] },
            "transport": {
                "proto": "xhttp",
                "options": { "mode": "stream", "host": sHost, "path": sPath },
                "tls": { "sni": sHost }
            }
        }]
    }, null, 2)
}
