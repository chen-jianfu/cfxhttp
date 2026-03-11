import { connect } from 'cloudflare:sockets'

// -----------------------------------------------------------------------------
// 全局参数配置
// -----------------------------------------------------------------------------
const AUTH_KEY = '96c50e3a-5b87-49dd-bd20-03c7f2735e40'
// 备用中继节点地址 (硬编码的兜底回退 IP)
const CF_FALLBACK_IPS = ['13.230.34.30']


// ✅ 新增：全局复用 TextDecoder（避免重复创建）
const TEXT_DECODER = new TextDecoder();
// -----------------------------------------------------------------------------
// 数据处理与校验工具
// -----------------------------------------------------------------------------


// ============================================================================
// 1. 全局初始化阶段 (只在 Worker 冷启动时运行一次)
// ============================================================================
const AUTH_CHUNKS = new Uint8Array(16);
// 将横杠去掉，提前准备好纯 16 进制字符串
const cleanHex = AUTH_KEY.replace(/-/g, '');
for (let i = 0; i < 16; i++) {
    AUTH_CHUNKS[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
}

// ============================================================================
// 2. 校验函数 (热点路径：极速零分配校验)
// 传入整个 buffer 和起始位置 offset，绝对不创建新对象！
// ============================================================================
function checkAuth(buffer, offset) {
    // 使用循环展开(Loop Unrolling)，比 for 循环更快，零内存分配
    return buffer[offset]      === AUTH_CHUNKS[0]  &&
           buffer[offset + 1]  === AUTH_CHUNKS[1]  &&
           buffer[offset + 2]  === AUTH_CHUNKS[2]  &&
           buffer[offset + 3]  === AUTH_CHUNKS[3]  &&
           buffer[offset + 4]  === AUTH_CHUNKS[4]  &&
           buffer[offset + 5]  === AUTH_CHUNKS[5]  &&
           buffer[offset + 6]  === AUTH_CHUNKS[6]  &&
           buffer[offset + 7]  === AUTH_CHUNKS[7]  &&
           buffer[offset + 8]  === AUTH_CHUNKS[8]  &&
           buffer[offset + 9]  === AUTH_CHUNKS[9]  &&
           buffer[offset + 10] === AUTH_CHUNKS[10] &&
           buffer[offset + 11] === AUTH_CHUNKS[11] &&
           buffer[offset + 12] === AUTH_CHUNKS[12] &&
           buffer[offset + 13] === AUTH_CHUNKS[13] &&
           buffer[offset + 14] === AUTH_CHUNKS[14] &&
           buffer[offset + 15] === AUTH_CHUNKS[15];
}

function mergeBuffer(a, b) {
    const c = new Uint8Array(a.length + b.length)
    c.set(a)
    c.set(b, a.length)
    return c
}

function isCFError(err) {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') || 
           msg.includes('cannot connect') || 
           msg.includes('cloudflare');
}

// -----------------------------------------------------------------------------
// 协议头解析器 (带自动扩容安全机制的极速版)
// -----------------------------------------------------------------------------
const PROTO_VER = 0;
const TYPE_TCP = 1;
const ADDR_V4 = 1;
const ADDR_DNS = 2;
const ADDR_V6 = 3;

async function resolveHeader(streamReader) {
    // 初始分配 4KB (足够应对 99% 的情况)，避免 XHTTP 大包溢出
    let buffer = new Uint8Array(4096); 
    let offset = 0;

    // 辅助函数：安全读取指定字节，带自动扩容机制
    const requireBytes = async (length) => {
        while (offset < length) {
            const { value, done } = await streamReader.read();
            if (done) return false;
            
            // 【核心修复】：如果发现数据块比当前的 buffer 还大，自动扩容！
            if (offset + value.length > buffer.length) {
                // 按 2 倍或实际需要的大小扩容
                const newSize = Math.max(buffer.length * 2, offset + value.length);
                const newBuffer = new Uint8Array(newSize);
                newBuffer.set(buffer); // 搬运老数据
                buffer = newBuffer;    // 替换成大容量的新数组
            }
            
            buffer.set(value, offset);
            offset += value.length;
        }
        return true;
    };

    if (!(await requireBytes(18))) return null;
    if (buffer[0] !== PROTO_VER) return { error: 'Err:V' };
    
    // UUID 校验 (配合之前的零分配 checkAuth)
    if (!checkAuth(buffer, 1)) return { error: 'Err:A' };

    const metaLen = buffer[17];
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

    if (addrType === ADDR_V4) {
        payloadStart = addrStart + 4;
        if (!(await requireBytes(payloadStart))) return null;
        targetAddr = `${buffer[addrStart]}.${buffer[addrStart+1]}.${buffer[addrStart+2]}.${buffer[addrStart+3]}`;
        
    } else if (addrType === ADDR_DNS) {
        if (!(await requireBytes(addrStart + 1))) return null;
        const dnsLen = buffer[addrStart];
        payloadStart = addrStart + 1 + dnsLen;
        if (!(await requireBytes(payloadStart))) return null;
        targetAddr = TEXT_DECODER.decode(buffer.subarray(addrStart + 1, payloadStart));
    } else if (addrType === ADDR_V6) {
        payloadStart = addrStart + 16;
        if (!(await requireBytes(payloadStart))) return null;
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(((buffer[addrStart + i] << 8) | buffer[addrStart + i + 1]).toString(16));
        }
        targetAddr = `[${parts.join(':')}]`;
    } else {
        return { error: `Err:T-${addrType}` };
    }

    // 将多读出来的数据（首帧 Payload）提取出来
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
           
 // ==========================================================
            // 🟢 上行流量：背压感知异步泵 (防丢尾数据版)
            // ==========================================================
// ==========================================================
// 🟢 上行流量：使用 pipeTo（自动背压 + 资源管理）
// ==========================================================
ctx.waitUntil((async () => {
    try {
        // 创建组合流：initialData + 剩余请求数据
        const combinedStream = new ReadableStream({
            async start(controller) {
                // 先注入 initialData
                if (headerInfo.initialData.length > 0) {
                    controller.enqueue(headerInfo.initialData);
                }
            },
            async pull(controller) {
                const { done, value } = await ingressReader.read();
                if (done) {
                    controller.close();
                } else {
                    controller.enqueue(value);
                }
            },
            cancel(reason) {
                ingressReader.cancel(reason);
            }
        });

        // 一行搞定：自动背压 + 自动关闭
        await combinedStream.pipeTo(egressSocket.writable);

    } catch (e) {
        // 忽略正常断开
    } finally {
        try { egressSocket.close(); } catch {}
    }
})());


            // ==========================================================
            // 🔵 下行流量：原生零拷贝通道
            // ==========================================================
            const feedbackHead = new Uint8Array([headerInfo.ver, 0]);
            const { readable: outputStream, writable: internalLink } = new TransformStream();
            
            ctx.waitUntil((async () => {
                try {
                    const feedbackWriter = internalLink.getWriter();
                    await feedbackWriter.write(feedbackHead);
                    feedbackWriter.releaseLock(); 
                    // 保持原生 pipeTo，极致下载速度，防断流
                    await egressSocket.readable.pipeTo(internalLink, { preventAbort: true }); 
                } catch (e) {
                }
            })());

return new Response(outputStream, {
    status: 200,
    headers: { 
        'Content-Type': 'application/octet-stream'
    }
});

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
