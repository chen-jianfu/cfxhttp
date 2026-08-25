// ============================================================
// VLESS + XHTTP (mode=stream-one) 精简独立版
// 从多协议 _worker.js 中分离而来，仅保留 vless over xhttp 核心代码
//
// 环境变量：
//   UUID                  客户端 UUID（未提供或非标准格式时由密码派生）
//   ADMIN/PASSWORD/TOKEN  未提供 UUID 时作为派生种子
//   PROXYIP               自定义反代 IP（多个逗号分隔随机选用）
//   DEBUG                 调试日志 ('1'/'true')
//   TCP_CONCURRENT_DIAL   直连并发拨号数（默认 2）
//   PROXY_CONCURRENT_DIAL 反代并发拨号数（默认 1）
// ============================================================

///////////////////////////////////////////////////////全局常量/////////////////////////////////////////////////
let 调试日志打印 = false;
const 上行合包目标字节 = 20 * 1024;
let TCP并发拨号数 = 2, 反代并发拨号数 = 1;

const 特征码字典 = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		调试日志打印 = ['1', 'true'].includes(env.DEBUG) || 调试日志打印;
		TCP并发拨号数 = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || TCP并发拨号数);
		反代并发拨号数 = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || 反代并发拨号数);

		const envUUID = env.UUID || env.uuid || '';
		const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
		if (!envUUID && !管理员密码) return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });

		let userID;
		if (envUUID && uuidRegex.test(envUUID)) userID = envUUID.toLowerCase();
		else userID = await 生成UUID格式ID(envUUID || 管理员密码);

		let 默认反代IP = (`${request.cf.colo}.${特征码字典[0]}.${特征码字典[1]}SsSs.nEt`).toLowerCase(), 默认反代兜底 = true;
		if (env.PROXYIP) {
			const proxyIPs = await 整理成数组(env.PROXYIP);
			默认反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			默认反代兜底 = false;
		}

		if (request.method === 'POST') {// XHTTP代理
			const 反代上下文 = await 反代参数获取(url, 默认反代IP, 默认反代兜底);
			log(`[叉HTTP] 命中请求: ${url.pathname}${url.search}`);
			return await 处理叉HTTP请求(request, userID, 反代上下文);
		} else if (url.pathname === '/status') {// 诊断接口
			const 目标UUID = String(userID);
			const 请求UUID = (url.searchParams.get('uuid') || '').toLowerCase();
			const { 头: Padding头, 键: Padding键 } = 获取叉HTTPPadding标识(userID);
			const 匹配 = 请求UUID === 目标UUID;
			return new Response(JSON.stringify({
				status: 'alive',
				uuidConfigured: !!(envUUID || 管理员密码),
				uuidMatch: 请求UUID ? 匹配 : null,
				uuidHint: 匹配 ? 目标UUID : 目标UUID.slice(0, 8) + '-****-****-****-' + 目标UUID.slice(-4) + '（追加?uuid=你的客户端UUID核对）',
				paddingHeader: Padding头,
				paddingKey: Padding键,
				反代IP: 默认反代IP,
				反代兜底: 默认反代兜底,
				hint: !请求UUID ? 'worker存活，追加 ?uuid=客户端UUID 核对是否一致'
					: (!匹配 ? '客户端UUID与Worker不一致：修改环境变量UUID或重新生成节点' : 'UUID一致，请检查节点参数 type=xhttp&mode=stream-one 及客户端内核版本'),
			}, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } });
		}

		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};

///////////////////////////////////////////////////////基础工具函数///////////////////////////////////////////////
function log(...args) {
	if (调试日志打印) console.log(...args);
}

function 数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

async function WebSocket发送并等待(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function 创建请求TCP连接器(request) {
	const 请求对象 = /** @type {any} */ (request);
	const fetcher = 请求对象?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}

async function MD5MD5(文本) {
	const 编码器 = new TextEncoder();
	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次十六进制 = Array.from(new Uint8Array(第一次哈希)).map(字节 => 字节.toString(16).padStart(2, '0')).join('');
	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	const 第二次十六进制 = Array.from(new Uint8Array(第二次哈希)).map(字节 => 字节.toString(16).padStart(2, '0')).join('');
	return 第二次十六进制.toLowerCase();
}

function 生成UUID格式ID(种子) {
	return MD5MD5(String(种子)).then(hash => [hash.slice(0, 8), hash.slice(8, 12), '4' + hash.slice(13, 16), '8' + hash.slice(17, 20), hash.slice(20)].join('-'));
}

async function 整理成数组(内容) {
	var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组;
}

function 反代参数获取(url, 默认反代IP = '', 默认反代兜底 = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let 反代IP = 默认反代IP, 启用反代兜底 = 默认反代兜底;

	const 设置反代IP = (值) => {
		反代IP = 值;
		启用反代兜底 = false;
	};

	const 提取路径值 = (值) => {
		if (!值.includes('://')) {
			const 斜杠索引 = 值.indexOf('/');
			return 斜杠索引 > 0 ? 值.slice(0, 斜杠索引) : 值;
		}
		const 协议拆分 = 值.split('://');
		if (协议拆分.length !== 2) return 值;
		const 斜杠索引 = 协议拆分[1].indexOf('/');
		return 斜杠索引 > 0 ? `${协议拆分[0]}://${协议拆分[1].slice(0, 斜杠索引)}` : 值;
	};

	const 查询反代IP = searchParams.get('proxyip');
	if (查询反代IP !== null && 查询反代IP !== '') {
		设置反代IP(查询反代IP);
	} else {
		const 匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower);
		if (匹配) 设置反代IP(提取路径值(匹配[2]));
	}
	return { 反代IP, 反代兜底: 启用反代兜底 };
}

///////////////////////////////////////////////////////VLESS协议解析///////////////////////////////////////////////
const UUID字节缓存 = new Map();
const 魏烈思文本解码器 = new TextDecoder();

function 读取十六进制半字节(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function 获取UUID字节(uuid) {
	const key = String(uuid || '');
	let cached = UUID字节缓存.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = 读取十六进制半字节(clean.charCodeAt(i * 2));
		const low = 读取十六进制半字节(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
	UUID字节缓存.set(key, bytes);
	return bytes;
}

function UUID字节匹配(data, offset, uuid) {
	const expected = 获取UUID字节(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function 解析魏烈思请求(chunk, token) {
	const data = 数据转Uint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUID字节匹配(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = 魏烈思文本解码器.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

///////////////////////////////////////////////////////XHTTP传输数据///////////////////////////////////////////////
const HPACKHuffman码长 = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function 获取叉HTTPPadding标识(yourUUID) {
	return { 头: yourUUID.slice(1, 7), 键: '_' + yourUUID.slice(25, 31) };
}

function 计算HPACKHuffman字节长度(字符串) {
	const 字节 = new TextEncoder().encode(字符串);
	let 总位数 = 0;
	for (let i = 0; i < 字节.length; i++) {
		总位数 += HPACKHuffman码长[字节[i]];
	}
	return Math.ceil(总位数 / 8);
}

function 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键) {
	const 头值 = request.headers.get(本机Padding头);
	if (头值) {
		try {
			const 解析URL = new URL(头值, 'https://x.invalid');
			const 查询值 = 解析URL.searchParams.get(本机Padding键);
			if (查询值) return 查询值;
		} catch (e) { }
		return 头值;
	}
	const 请求URL = new URL(request.url);
	return 请求URL.searchParams.get(本机Padding键) || '';
}

function 校验叉HTTPPadding(request, 本机Padding头, 本机Padding键) {
	const padding值 = 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键);
	if (!padding值) return true;
	const huffman长度 = 计算HPACKHuffman字节长度(padding值);
	return huffman长度 >= 98 && huffman长度 <= 1002;
}

const 叉HTTPBase62字符集 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function 生成叉HTTPPadding串(长度) {
	const 字符集长度 = 叉HTTPBase62字符集.length;
	let 结果 = '';
	for (let i = 0; i < 长度; i++) {
		结果 += 叉HTTPBase62字符集[Math.floor(Math.random() * 字符集长度)];
	}
	return 结果;
}

async function 读取叉HTTP首包(reader, token) {
	const decoder = 魏烈思文本解码器;

	const 尝试解析魏烈思首包 = (data) => {
		const length = data.byteLength;
		if (length < 18) return { 状态: 'need_more' };
		if (!UUID字节匹配(data, 1, token)) return { 状态: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { 状态: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { 状态: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { 状态: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { 状态: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };

		return {
			状态: 'ok',
			结果: {
				协议: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				原始数据: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const 当前数据 = buffer.subarray(0, offset);
		const 魏烈思结果 = 尝试解析魏烈思首包(当前数据);
		if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };
		if (魏烈思结果.状态 === 'invalid') return null;
	}

	const 最终数据 = buffer.subarray(0, offset);
	const 最终魏烈思结果 = 尝试解析魏烈思首包(最终数据);
	if (最终魏烈思结果.状态 === 'ok') return { ...最终魏烈思结果.结果, reader };
	return null;
}

async function 处理叉HTTP请求(request, yourUUID, 反代上下文 = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(yourUUID);
	if (!校验叉HTTPPadding(request, 本机Padding头, 本机Padding键)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取叉HTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	log(`[叉HTTP] 首包解析成功: ${首包.hostname}:${首包.port} | UDP: ${首包.isUDP ? '是' : '否'}`);
	if (首包.isUDP && 首包.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const 响应URL = new URL('https://x.invalid/');
		响应URL.searchParams.set(本机Padding键, 生成叉HTTPPadding串(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(本机Padding头, 响应URL.toString());
	} catch (e) { }

	if (首包.isUDP) return 处理叉HTTPUDP请求(首包, reader, request, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const abortController = new AbortController();
	let 已清理 = false;
	let 远端Socket = null;
	const 清理 = (reason) => {
		if (已清理) return;
		已清理 = true;
		log(`[叉HTTP] 会话关闭: ${reason?.message || reason || '正常结束'}`);
		try { abortController.abort(reason) } catch (e) { }
		try { 远端Socket?.close?.() } catch (e) { }
	};

	let socket;
	try {
		socket = await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, request, 反代上下文);
	} catch (err) {
		log(`[叉HTTP-Pipe] 连接失败: ${err?.message || err}`);
		清理(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		清理(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}
	远端Socket = socket;

	let 上行字节 = 0, 下行字节 = 0;
	const 上行Promise = (async () => {
		const 上行合包器 = 创建上行Grain合包流();
		const 搬运Promise = 上行合包器.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void 搬运Promise.catch(err => {
			log(`[叉HTTP] 上行搬运失败: ${err?.message || err}`);
			清理(err);
			throw err;
		});
		const 上行reader = request.body.getReader();
		const 取消上行reader = () => {
			try { 上行reader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', 取消上行reader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await 上行reader.read();
					if (done) break;
					if (value?.byteLength) {
						上行字节 += value.byteLength;
						await 上行合包器.写入(value);
					}
				}
			} finally {
				abortController.signal.removeEventListener('abort', 取消上行reader);
				try { 上行reader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await 上行合包器.结束() } catch (e) { }
		}
		await 搬运Promise;
	})();

	const 响应流 = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const 下行Promise = (async () => {
		const 计数流 = new TransformStream({
			transform(chunk, controller) {
				下行字节 += chunk?.byteLength || 0;
				controller.enqueue(chunk);
			}
		});
		const writer = 响应流.writable.getWriter();
		try {
			if (有效数据长度(首包.respHeader) > 0) await writer.write(首包.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeThrough(计数流).pipeTo(响应流.writable, { signal: abortController.signal });
	})();

	void 上行Promise.then(() => log(`[叉HTTP] 上行完成: 共${上行字节}B`), err => {
		log(`[叉HTTP] 上行异常: ${err?.message || err}`);
		清理(err);
	});
	void 下行Promise.then(() => {
		log(`[叉HTTP] 下行完成: 共${下行字节}B`);
		清理();
	}, err => {
		log(`[叉HTTP] 下行异常: ${err?.message || err} | 已收${下行字节}B`);
		清理(err);
	});
	void Promise.allSettled([上行Promise, 下行Promise]);

	return new Response(响应流.readable, { status: 200, headers: responseHeaders });
}

function 处理叉HTTPUDP请求(首包, reader, request, responseHeaders) {
	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let udpRespHeader = 首包.respHeader;
			const 叉桥 = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						已关闭 = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (已关闭) return;
					已关闭 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			try {
				if (首包.rawData?.byteLength) {
					await forwardataudp(首包.rawData, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					await forwardataudp(value, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				log(`[叉HTTP转发] 处理失败: ${err?.message || err}`);
				closeSocketQuietly(叉桥);
			} finally {
				closeSocketQuietly(叉桥);
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function 创建上行Grain合包流(目标字节 = 上行合包目标字节) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const 缓冲 = new Uint8Array(目标字节);
	let 缓冲长度 = 0;
	let 定时器 = null;
	let 在途写 = null;
	let 冲刷链 = Promise.resolve();

	const 清理定时器 = () => {
		if (定时器) {
			clearTimeout(定时器);
			定时器 = null;
		}
	};

	const 串行写 = async (chunk) => {
		if (在途写) await 在途写;
		在途写 = writer.write(chunk);
		try { await 在途写 } finally { 在途写 = null; }
	};

	const 冲刷 = async () => {
		if (缓冲长度) {
			const chunk = 缓冲.slice(0, 缓冲长度);
			缓冲长度 = 0;
			await 串行写(chunk);
		}
	};

	const 排队冲刷 = () => {
		冲刷链 = 冲刷链.then(() => 冲刷()).catch(() => { });
	};

	const 启动定时器 = () => {
		if (定时器) return;
		定时器 = setTimeout(() => {
			定时器 = null;
			排队冲刷();
		}, 1);
	};

	return {
		readable: identity.readable,
		写入: async (chunk) => {
			const data = 数据转Uint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= 目标字节) {
				清理定时器();
				if (缓冲长度) await 冲刷();
				await 串行写(data);
				return;
			}
			if (缓冲长度 + data.byteLength >= 目标字节) {
				const output = new Uint8Array(缓冲长度 + data.byteLength);
				output.set(缓冲.subarray(0, 缓冲长度), 0);
				output.set(data, 缓冲长度);
				缓冲长度 = 0;
				清理定时器();
				await 串行写(output);
			} else {
				缓冲.set(data, 缓冲长度);
				缓冲长度 += data.byteLength;
				启动定时器();
			}
		},
		结束: async () => {
			清理定时器();
			try {
				await 冲刷链;
				await 冲刷();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

///////////////////////////////////////////////////////TCP转发///////////////////////////////////////////////
async function forwardataTCP(host, portNum, rawData, request = null, 反代上下文 = {}) {
	const ctx反代IP = 反代上下文.反代IP || '';
	const ctx反代兜底 = 反代上下文.反代兜底 !== undefined ? 反代上下文.反代兜底 : true;
	let 反代数组索引 = 0;
	log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${ctx反代IP} | 反代兜底: ${ctx反代兜底 ? '是' : '否'}`);
	const 连接超时毫秒 = 1000;
	const TCP连接 = 创建请求TCP连接器(request);

	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
		]);
	}

	async function 打开TCP连接(address, port) {
		const remoteSock = TCP连接({ hostname: address, port });
		try {
			await 等待连接建立(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function 写入首包(remoteSock, data) {
		if (有效数据长度(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(数据转Uint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
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

	async function connectDirect(address, port, data = null) {
		const 候选列表 = Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(`[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
		let socket = null;
		try {
			const 连接结果 = await 并发打开候选连接(候选列表);
			socket = 连接结果.socket;
			await 写入首包(socket, data);
			log(`[TCP直连] 直连成功: ${address}:${port} | 首包 ${有效数据长度(data)}B`);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, 所有反代数组 = null, 启用反代失败兜底 = true) {
		if (所有反代数组 && 所有反代数组.length > 0) {
			const 实际并发数 = Math.max(1, Math.floor(Number(反代并发拨号数) || 1));
			for (let i = 0; i < 所有反代数组.length; i += 实际并发数) {
				const 候选列表 = [];
				for (let j = 0; j < 实际并发数 && i + j < 所有反代数组.length; j++) {
					const 索引 = (反代数组索引 + i + j) % 所有反代数组.length;
					const [反代地址, 反代端口] = 所有反代数组[索引];
					候选列表.push({ hostname: 反代地址, port: 反代端口, index: 索引 });
				}
				let socket = null, candidate = null;
				try {
					log(`[反代连接] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const 连接结果 = await 并发打开候选连接(候选列表);
					socket = 连接结果.socket;
					candidate = 连接结果.candidate;
					await 写入首包(socket, data);
					log(`[反代连接] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
					反代数组索引 = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[反代连接] 本批连接失败: ${err.message || err}`);
				}
			}
		}

		if (启用反代失败兜底) return connectDirect(address, port, data);
		else {
			throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
		}
	}

	try {
		log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
		return await connectDirect(host, portNum, rawData);
	} catch (err) {
		log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
		const 所有反代数组 = await 解析地址端口(ctx反代IP, host);
		return await connectProxyIP(`${特征码字典[0]}.tp1.${特征码字典[2]}.xyz`, 1, rawData, 所有反代数组, ctx反代兜底);
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, 响应封装器 = null) {
	const 请求数据 = 数据转Uint8Array(udpChunk);
	const 请求字节数 = 请求数据.byteLength;
	log(`[UDP转发] 收到 DNS 请求: ${请求字节数}B -> 8.8.4.4:53`);
	try {
		const TCP连接 = 创建请求TCP连接器(request);
		const tcpSocket = TCP连接({ hostname: '8.8.4.4', port: 53 });
		let 魏烈思Header = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(请求数据);
		log(`[UDP转发] DNS 请求已写入上游: ${请求字节数}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const 原始响应 = 数据转Uint8Array(chunk);
				log(`[UDP转发] 收到 DNS 响应: ${原始响应.byteLength}B`);
				const 封装结果 = 响应封装器 ? await 响应封装器(原始响应) : 原始响应;
				const 发送片段列表 = Array.isArray(封装结果) ? 封装结果 : [封装结果];
				if (!发送片段列表.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of 发送片段列表) {
					const 转发响应 = 数据转Uint8Array(fragment);
					if (!转发响应.byteLength) continue;
					if (魏烈思Header) {
						const response = new Uint8Array(魏烈思Header.length + 转发响应.byteLength);
						response.set(魏烈思Header, 0);
						response.set(转发响应, 魏烈思Header.length);
						await WebSocket发送并等待(webSocket, response.buffer);
						魏烈思Header = null;
					} else {
						await WebSocket发送并等待(webSocket, 转发响应);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
	}
}

///////////////////////////////////////////////////////DoH与反代解析///////////////////////////////////////////////
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
		log(`[DoH查询] 命中缓存 ${域名} ${记录类型} via ${DoH解析服务}`);
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

		log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
		const response = await fetch(DoH解析服务, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
			return [];
		}

		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

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
			offset = /** @type {number} */ (end) + 4;
		}

		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = 解析域名(offset);
			offset = /** @type {number} */ (nameEnd);
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
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		log(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果`);
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
			log(`[DoH查询] 写入缓存 ${域名} ${记录类型} TTL=${缓存TTL}s`);
		}
		return answers;
	} catch (error) {
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
		return [];
	}
}

async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function 解析地址端口字符串(str) {
		let 地址 = str, 端口 = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			地址 = parts[0] + ']';
			端口 = parseInt(parts[1], 10) || 端口;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			地址 = str.slice(0, colonIndex);
			端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
		}
		return [地址, 端口];
	}

	function 解析TXT反代记录(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => 解析地址端口字符串(prefix));
	}

	const 反代IP数组 = await 整理成数组(proxyIP);
	let 所有反代数组 = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	for (const singleProxyIP of 反代IP数组) {
		let [地址, 端口] = 解析地址端口字符串(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
		}

		if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
			log(`[反代解析] ${地址} 为IP地址，直接使用`);
			所有反代数组.push([地址, 端口]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			DoH查询(地址, 'TXT'),
			DoH查询(地址, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = 解析TXT反代记录(txtData);
		if (txtAddresses.length > 0) {
			log(`[反代解析] ${地址} 使用TXT记录，共${txtAddresses.length}个结果`);
			所有反代数组.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[反代解析] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
			所有反代数组.push(...ipv4List.map(ip => [ip, 端口]));
			continue;
		}

		const aaaaRecords = await DoH查询(地址, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[反代解析] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
			所有反代数组.push(...ipv6List.map(ip => [ip, 端口]));
		} else {
			log(`[反代解析] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
			所有反代数组.push([地址, 端口]);
		}
	}
	const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
	const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
	let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`)
	const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const 解析结果 = 洗牌后.slice(0, 8);
	log(`[反代解析] 解析完成 总数: ${解析结果.length}个\n${解析结果.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 解析结果;
}

///////////////////////////////////////////////////////HTML伪装页面///////////////////////////////////////////////
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
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
	</html>
	`
}
