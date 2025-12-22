import { connect } from 'cloudflare:sockets'

// -----------------------------------------------------------------------------
// 配置区域
// -----------------------------------------------------------------------------
const UUID_STR = '96c50e3a-5b87-49dd-bd20-03c7f2735e40'
// 这里填入有效的 ProxyIP，通常是优选 IP 或专门的中转域名
const PROXY = 'ProxyIP.Multacom.CMLiussss.net' 

// -----------------------------------------------------------------------------
// 全局预处理
// -----------------------------------------------------------------------------
const UUID_BYTES = new Uint8Array(16)
for (let i = 0; i < 16; i++) {
    UUID_BYTES[i] = parseInt(UUID_STR.replace(/-/g, '').substr(i * 2, 2), 16)
}

function join_array(a, b) {
    const c = new Uint8Array(a.length + b.length)
    c.set(a)
    c.set(b, a.length)
    return c
}

function validate_uuid(id) {
    for (let i = 0; i < 16; i++) {
        if (id[i] !== UUID_BYTES[i]) return false
    }
    return true
}

// -----------------------------------------------------------------------------
// VLESS 解析 (保持不变)
// -----------------------------------------------------------------------------
const VLESS_VERSION = 0
const CMD_TCP = 1
const ADDR_TYPE_IPV4 = 1
const ADDR_TYPE_DOMAIN = 2
const ADDR_TYPE_IPV6 = 3

async function parse_vless_header(reader) {
    let buffer = new Uint8Array(0)
    while (buffer.length < 18) {
        const { value, done } = await reader.read()
        if (done) return null
        buffer = join_array(buffer, value)
    }
    if (buffer[0] !== VLESS_VERSION) return { error: 'Invalid Version' }
    if (!validate_uuid(buffer.subarray(1, 17))) return { error: 'Invalid UUID' }
    const optLen = buffer[17]
    let currentNeed = 18 + optLen + 4 
    while (buffer.length < currentNeed) {
        const { value, done } = await reader.read()
        if (done) return null
        buffer = join_array(buffer, value)
    }
    const cmd = buffer[18 + optLen]
    if (cmd !== CMD_TCP) return { error: `Unsupported Command: ${cmd}` }

    const portIndex = 18 + optLen + 1
    const port = (buffer[portIndex] << 8) | buffer[portIndex + 1]
    const addrType = buffer[portIndex + 2]
    const addrStartIndex = portIndex + 3
    let address = ''
    let bodyStartIndex = 0

    if (addrType === ADDR_TYPE_IPV4) {
        currentNeed = addrStartIndex + 4
        while (buffer.length < currentNeed) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        address = buffer.subarray(addrStartIndex, addrStartIndex + 4).join('.')
        bodyStartIndex = addrStartIndex + 4
    } else if (addrType === ADDR_TYPE_DOMAIN) {
        if (buffer.length < addrStartIndex + 1) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        const domainLen = buffer[addrStartIndex]
        currentNeed = addrStartIndex + 1 + domainLen
        while (buffer.length < currentNeed) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        address = new TextDecoder().decode(buffer.subarray(addrStartIndex + 1, addrStartIndex + 1 + domainLen))
        bodyStartIndex = addrStartIndex + 1 + domainLen
    } else if (addrType === ADDR_TYPE_IPV6) {
        currentNeed = addrStartIndex + 16
        while (buffer.length < currentNeed) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        const ipv6 = buffer.subarray(addrStartIndex, addrStartIndex + 16)
        address = `[${Array.from(ipv6).map(b => b.toString(16).padStart(2, '0')).join(':').match(/.{1,4}/g).join(':')}]`
        bodyStartIndex = addrStartIndex + 16
    } else {
        return { error: `Unknown Address Type: ${addrType}` }
    }
    return { address, port, headData: buffer.subarray(bodyStartIndex), version: buffer[0] }
}

// -----------------------------------------------------------------------------
// 主逻辑 (已修复 Proxy 支持)
// -----------------------------------------------------------------------------
export default {
    async fetch(request, env, ctx) {
        const _UUID = env.UUID || UUID_STR
        const _PROXY = env.PROXY || PROXY // 获取 ProxyIP
        
        if (request.method === 'GET') {
            const url = new URL(request.url)
            if (url.pathname.includes(_UUID) || url.search.includes(_UUID)) {
                return new Response(generate_config(url, _UUID), { headers: { 'Content-Type': 'application/json' } })
            }
            return new Response('Worker is running.', { status: 200 })
        }

        if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 })

        try {
            const requestReader = request.body.getReader()
            const vless = await parse_vless_header(requestReader)
            
            if (!vless) return new Response('Header too short', { status: 400 })
            if (vless.error) {
                requestReader.releaseLock() 
                return new Response(vless.error, { status: 400 })
            }

            // ============================================================
            // 核心修改：连接逻辑 (直连 -> 失败 -> Proxy)
            // ============================================================
            let remoteSocket
            try {
                // 1. 尝试直连目标
                remoteSocket = connect({ hostname: vless.address, port: vless.port })
                await remoteSocket.opened
            } catch (err) {
                // console.log(`Direct connect failed to ${vless.address}, trying proxy...`)
                
                // 2. 直连失败，检查是否有 Proxy 配置
                if (_PROXY) {
                    try {
                        // 尝试连接 ProxyIP，但端口依然是目标的端口
                        // 这一步利用了 SNI 分流特性：TCP 连接到 ProxyIP，但 TLS 握手里的域名还是原目标
                        remoteSocket = connect({ hostname: _PROXY, port: vless.port })
                        await remoteSocket.opened
                    } catch (e) {
                        // Proxy 也连不上，彻底放弃
                        requestReader.releaseLock()
                        return new Response(`Connect Failed: ${err.message} & Proxy Error`, { status: 502 })
                    }
                } else {
                    requestReader.releaseLock()
                    return new Response(`Connect Failed: ${err.message}`, { status: 502 })
                }
            }
            // ============================================================

            const remoteWriter = remoteSocket.writable.getWriter()
            
            // 上行
            ctx.waitUntil((async () => {
                try {
                    if (vless.headData.length > 0) await remoteWriter.write(vless.headData)
                    while (true) {
                        const { done, value } = await requestReader.read()
                        if (done) break
                        await remoteWriter.write(value)
                    }
                } catch (e) {} finally {
                    remoteWriter.close()
                }
            })())

            // 下行 (零拷贝)
            const responseHeader = new Uint8Array([vless.version, 0])
            const { readable: clientReadable, writable: clientWritable } = new TransformStream()
            const clientWriter = clientWritable.getWriter()
            
            ctx.waitUntil((async () => {
                try {
                    await clientWriter.write(responseHeader)
                    clientWriter.releaseLock() 
                    await remoteSocket.readable.pipeTo(clientWritable) 
                } catch (e) {}
            })())

            return new Response(clientReadable, {
                status: 200,
                headers: { 'Connection': 'keep-alive', 'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no' }
            })

        } catch (err) {
            return new Response(err.message, { status: 500 })
        }
    }
}

function generate_config(url, uuid) {
    const host = url.hostname
    const path = url.pathname.endsWith('/') ? url.pathname : `${url.pathname}/`
    return JSON.stringify({
        "log": { "loglevel": "warning" },
        "inbounds": [{ "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": {} }],
        "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{ "address": host, "port": 443, "users": [{ "id": uuid, "encryption": "none" }] }] },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": { "mode": "stream-one", "host": host, "path": path },
                "security": "tls",
                "tlsSettings": { "serverName": host }
            }
        }]
    }, null, 2)
}
