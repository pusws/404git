//nat64自动填充proxyip，无需且不支持proxyip设置
import { connect } from "cloudflare:sockets";
const WS_READY_STATE_OPEN = 1;
let userID = "4b9f5f95-5c8e-4e5d-9d67-159f9c5845b7";
const cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
// http_ip
let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP3 = '\u0061\u0066\u0072\u0069\u0063\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP4 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
let IP5 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074'
let IP6 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074'
let IP7 = '\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d'

// https_ip
let IP8 = '\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP9 = '\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP10 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077'
let IP11 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068'
let IP12 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072'
let IP13 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d'

// http_port
let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

// https_port
let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

export default {
	/**
	 * @param {any} request
	 * @param {{uuid: string, proxyip: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string}} env
	 * @param {any} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			userID = env.uuid || userID;
			CDNIP = env.cdnip || CDNIP;
			IP1 = env.ip1 || IP1;
			IP2 = env.ip2 || IP2;
			IP3 = env.ip3 || IP3;
			IP4 = env.ip4 || IP4;
			IP5 = env.ip5 || IP5;
			IP6 = env.ip6 || IP6;
			IP7 = env.ip7 || IP7;
			IP8 = env.ip8 || IP8;
			IP9 = env.ip9 || IP9;
			IP10 = env.ip10 || IP10;
			IP11 = env.ip11 || IP11;
			IP12 = env.ip12 || IP12;
			IP13 = env.ip13 || IP13;
			PT1 = env.pt1 || PT1;
			PT2 = env.pt2 || PT2;
			PT3 = env.pt3 || PT3;
			PT4 = env.pt4 || PT4;
			PT5 = env.pt5 || PT5;
			PT6 = env.pt6 || PT6;
			PT7 = env.pt7 || PT7;
			PT8 = env.pt8 || PT8;
			PT9 = env.pt9 || PT9;
			PT10 = env.pt10 || PT10;
			PT11 = env.pt11 || PT11;
			PT12 = env.pt12 || PT12;
			PT13 = env.pt13 || PT13;
			const upgradeHeader = request.headers.get("Upgrade");
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== "websocket") {
				const url = new URL(request.url);
				switch (url.pathname) {
					case `/${userID}`: {
						const vlessConfig = getVlessConfig(userID, request.headers.get("Host"));
						return new Response(vlessConfig, {
							status: 200,
							headers: {
								"Content-Type": "text/html;charset=utf-8",
							},
						});
					}
					case `/${userID}/ty`: {
						const tyConfig = gettyConfig(userID, request.headers.get('Host'));
						return new Response(`${tyConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					case `/${userID}/cl`: {
						const clConfig = getclConfig(userID, request.headers.get('Host'));
						return new Response(`${clConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					case `/${userID}/sb`: {
						const sbConfig = getsbConfig(userID, request.headers.get('Host'));
						return new Response(`${sbConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "application/json;charset=utf-8",
							}
						});
					}
					case `/${userID}/pty`: {
						const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
						return new Response(`${ptyConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					case `/${userID}/pcl`: {
						const pclConfig = getpclConfig(userID, request.headers.get('Host'));
						return new Response(`${pclConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					case `/${userID}/psb`: {
						const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
						return new Response(`${psbConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "application/json;charset=utf-8",
							}
						});
					}
					default:
						if (cn_hostnames.includes('')) {
							return new Response(JSON.stringify(request.cf, null, 4), {
								status: 200,
								headers: {
									"Content-Type": "application/json;charset=utf-8",
								},
							});
						}
						const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
						const newHeaders = new Headers(request.headers);
						newHeaders.set("cf-connecting-ip", "1.2.3.4");
						newHeaders.set("x-forwarded-for", "1.2.3.4");
						newHeaders.set("x-real-ip", "1.2.3.4");
						newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
						const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
						let modifiedRequest = new Request(proxyUrl, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: "manual",
						});
						const proxyResponse = await fetch(modifiedRequest, {
							redirect: "manual"
						});
						if ([301, 302].includes(proxyResponse.status)) {
							return new Response(`Redirects to ${randomHostname} are not allowed.`, {
								status: 403,
								statusText: "Forbidden",
							});
						}
						return proxyResponse;
				}
			}
			return await handleVlessWebSocket(request);
		} catch (err) {
			let e = err;
			return new Response(e.toString());
		}
	},
};

async function handleVlessWebSocket(request) {
	const wsPair = new WebSocketPair();
	const [clientWS, serverWS] = Object.values(wsPair);

	serverWS.accept();

	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
	let remoteSocket = null;

	let udpStreamWrite = null;
	let isDns = false;

	wsReadable.pipeTo(new WritableStream({
		async write(chunk) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}

			if (remoteSocket) {
				const writer = remoteSocket.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const result = parseVlessHeader(chunk, userID);
			if (result.hasError) {
				throw new Error(result.message);
			}

			const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
			const rawClientData = chunk.slice(result.rawDataIndex);

			if (result.isUDP) {
				if (result.portRemote === 53) {
					isDns = true;
					const {
						write
					} = await handleUDPOutBound(serverWS, vlessRespHeader);
					udpStreamWrite = write;
					udpStreamWrite(rawClientData);
					return;
				} else {
					throw new Error('UDP代理仅支持DNS(端口53)');
				}
			}

			async function connectAndWrite(address, port) {
				const tcpSocket = await connect({
					hostname: address,
					port: port
				});
				remoteSocket = tcpSocket;
				const writer = tcpSocket.writable.getWriter();
				await writer.write(rawClientData);
				writer.releaseLock();
				return tcpSocket;
			}

			function convertToNAT64IPv6(ipv4Address) {
				const parts = ipv4Address.split('.');
				if (parts.length !== 4) {
					throw new Error('无效的IPv4地址');
				}
				const hex = parts.map(part => {
					const num = parseInt(part, 10);
					if (num < 0 || num > 255) {
						throw new Error('无效的IPv4地址段');
					}
					return num.toString(16).padStart(2, '0');
				});
				const prefixes = ['2602:fc59:b0:64::'];
				const chosenPrefix = prefixes[Math.floor(Math.random() * prefixes.length)];
				return `[${chosenPrefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
			}

			async function getIPv6ProxyAddress(domain) {
				try {
					const dnsQuery = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
						headers: {
							'Accept': 'application/dns-json'
						}
					});
					const dnsResult = await dnsQuery.json();
					if (dnsResult.Answer && dnsResult.Answer.length > 0) {
						const aRecord = dnsResult.Answer.find(record => record.type === 1);
						if (aRecord) {
							const ipv4Address = aRecord.data;
							return convertToNAT64IPv6(ipv4Address);
						}
					}
					throw new Error('无法解析域名的IPv4地址');
				} catch (err) {
					throw new Error(`DNS解析失败: ${err.message}`);
				}
			}

			async function retry() {
				try {
					const proxyIP = await getIPv6ProxyAddress(result.addressRemote);
					console.log(`尝试通过NAT64 IPv6地址 ${proxyIP} 连接...`);
					const tcpSocket = await connect({
						hostname: proxyIP,
						port: result.portRemote
					});
					remoteSocket = tcpSocket;
					const writer = tcpSocket.writable.getWriter();
					await writer.write(rawClientData);
					writer.releaseLock();
					tcpSocket.closed.catch(error => {
						console.error('NAT64 IPv6连接关闭错误:', error);
					}).finally(() => {
						if (serverWS.readyState === WS_READY_STATE_OPEN) {
							serverWS.close(1000, '连接已关闭');
						}
					});
					pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, null);
				} catch (err) {
					console.error('NAT64 IPv6连接失败:', err);
					serverWS.close(1011, 'NAT64 IPv6连接失败: ' + err.message);
				}
			}

			try {
				const tcpSocket = await connectAndWrite(result.addressRemote, result.portRemote);
				pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, retry);
			} catch (err) {
				console.error('连接失败:', err);
				serverWS.close(1011, '连接失败');
			}
		},
		close() {
			if (remoteSocket) {
				closeSocket(remoteSocket);
			}
		}
	})).catch(err => {
		console.error('WebSocket 错误:', err);
		closeSocket(remoteSocket);
		serverWS.close(1011, '内部错误');
	});

	return new Response(null, {
		status: 101,
		webSocket: clientWS,
	});
}

function createWebSocketReadableStream(ws, earlyDataHeader) {
	return new ReadableStream({
		start(controller) {
			ws.addEventListener('message', event => {
				controller.enqueue(event.data);
			});
			ws.addEventListener('close', () => {
				controller.close();
			});
			ws.addEventListener('error', err => {
				controller.error(err);
			});
			if (earlyDataHeader) {
				try {
					const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
					const data = Uint8Array.from(decoded, c => c.charCodeAt(0));
					controller.enqueue(data.buffer);
				} catch (e) {}
			}
		}
	});
}

function parseVlessHeader(buffer, userID) {
	if (buffer.byteLength < 24) {
		return {
			hasError: true,
			message: '无效的头部长度'
		};
	}
	const view = new DataView(buffer);
	const version = new Uint8Array(buffer.slice(0, 1));
	const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
	if (uuid !== userID) {
		return {
			hasError: true,
			message: '无效的用户'
		};
	}
	const optionsLength = view.getUint8(17);
	const command = view.getUint8(18 + optionsLength);
	let isUDP = false;
	if (command === 1) {} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: '不支持的命令，仅支持TCP(01)和UDP(02)'
		};
	}
	let offset = 19 + optionsLength;
	const port = view.getUint16(offset);
	offset += 2;
	const addressType = view.getUint8(offset++);
	let address = '';
	switch (addressType) {
		case 1:
			address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
			offset += 4;
			break;
		case 2:
			const domainLength = view.getUint8(offset++);
			address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
			offset += domainLength;
			break;
		case 3:
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
				offset += 2;
			}
			address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
			break;
		default:
			return {
				hasError: true,
				message: '不支持的地址类型'
			};
	}
	return {
		hasError: false,
		addressRemote: address,
		portRemote: port,
		rawDataIndex: offset,
		vlessVersion: version,
		isUDP
	};
}

function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader, retry = null) {
	let headerSent = false;
	let hasIncomingData = false;
	remoteSocket.readable.pipeTo(new WritableStream({
		write(chunk) {
			hasIncomingData = true;
			if (ws.readyState === WS_READY_STATE_OPEN) {
				if (!headerSent) {
					const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
					combined.set(new Uint8Array(vlessHeader), 0);
					combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
					ws.send(combined.buffer);
					headerSent = true;
				} else {
					ws.send(chunk);
				}
			}
		},
		close() {
			if (!hasIncomingData && retry) {
				retry();
				return;
			}
			if (ws.readyState === WS_READY_STATE_OPEN) {
				ws.close(1000, '正常关闭');
			}
		},
		abort() {
			closeSocket(remoteSocket);
		}
	})).catch(err => {
		console.error('数据转发错误:', err);
		closeSocket(remoteSocket);
		if (ws.readyState === WS_READY_STATE_OPEN) {
			ws.close(1011, '数据传输错误');
		}
	});
}

function closeSocket(socket) {
	if (socket) {
		try {
			socket.close();
		} catch (e) {}
	}
}

function formatUUID(bytes) {
	const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

async function handleUDPOutBound(webSocket, vlessResponseHeader) {
	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {},
		transform(chunk, controller) {
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPacketLength)
				);
				index = index + 2 + udpPacketLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {}
	});
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch('https://1.1.1.1/dns-query', {
				method: 'POST',
				headers: {
					'content-type': 'application/dns-message',
				},
				body: chunk,
			})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				console.log(`DNS查询成功，DNS消息长度为 ${udpSize}`);
				if (isVlessHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		console.error('DNS UDP处理错误:', error);
	});
	const writer = transformStream.writable.getWriter();
	return {
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/**
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function getVlessConfig(userID, hostName) {
	const wVlessws = `vless://${userID}@${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
	const pVlesswstls = `vless://${userID}@${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
	const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP使用nat64自动生成，无需设置`;
	const ty = `https://${hostName}/${userID}/ty`;
	const cl = `https://${hostName}/${userID}/cl`;
	const sb = `https://${hostName}/${userID}/sb`;
	const pty = `https://${hostName}/${userID}/pty`;
	const pcl = `https://${hostName}/${userID}/pcl`;
	const psb = `https://${hostName}/${userID}/psb`;
	const wkShare = btoa(`vless://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
	const pgShare = btoa(`vless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);

	const displayHtml = `
	<!DOCTYPE html>
	<html lang="zh-CN">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>VLESS 配置中心</title>
		<link rel="icon" href="https://www.cloudflare.com/favicon.ico" type="image/x-icon">
		<script src="https://cdn.jsdelivr.net/npm/qrious/dist/qrious.min.js"></script>
		<style>
			:root {
				--font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Inter", "Segoe UI", Helvetica, Arial, sans-serif;
				/* 增强的浅色主题 */
				--bg-light: linear-gradient(135deg, #f8faff 0%, #f0f4ff 100%);
				--card-bg-light: rgba(255, 255, 255, 0.95);
				--sidebar-bg-light: rgba(255, 255, 255, 0.9);
				--text-light: #1a1d29;
				--text-muted-light: #6b7280;
				--border-light: rgba(99, 102, 241, 0.15);
				--accent-color-light: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
				--accent-hover-light: linear-gradient(135deg, #5a67d8 0%, #6c5ce7 100%);
				--shadow-light: rgba(99, 102, 241, 0.15);
				--glow-light: rgba(99, 102, 241, 0.25);
				/* 增强的深色主题 */
				--bg-dark: linear-gradient(135deg, #0c0e1a 0%, #1a1d29 100%);
				--card-bg-dark: rgba(30, 33, 48, 0.95);
				--sidebar-bg-dark: rgba(20, 23, 35, 0.95);
				--text-dark: #f8fafc;
				--text-muted-dark: #94a3b8;
				--border-dark: rgba(148, 163, 184, 0.15);
				--accent-color-dark: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
				--accent-hover-dark: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%);
				--shadow-dark: rgba(0, 0, 0, 0.4);
				--glow-dark: rgba(148, 163, 184, 0.2);
				/* 状态颜色 */
				--success-color: linear-gradient(135deg, #10b981 0%, #059669 100%);
				--warning-color: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
				--error-color: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
				/* 动画变量 */
				--animation-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
				--animation-normal: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
				--animation-slow: 0.5s cubic-bezier(0.4, 0, 0.2, 1);
			}
			html.dark {
				--bg: var(--bg-dark);
				--card-bg: var(--card-bg-dark);
				--sidebar-bg: var(--sidebar-bg-dark);
				--text-primary: var(--text-dark);
				--text-muted: var(--text-muted-dark);
				--border-color: var(--border-dark);
				--accent-color: var(--accent-color-dark);
				--accent-hover: var(--accent-hover-dark);
				--shadow-color: var(--shadow-dark);
				--glow-color: var(--glow-dark);
			}
			html:not(.dark) {
				--bg: var(--bg-light);
				--card-bg: var(--card-bg-light);
				--sidebar-bg: var(--sidebar-bg-light);
				--text-primary: var(--text-light);
				--text-muted: var(--text-muted-light);
				--border-color: var(--border-light);
				--accent-color: var(--accent-color-light);
				--accent-hover: var(--accent-hover-light);
				--shadow-color: var(--shadow-light);
				--glow-color: var(--glow-light);
			}
			* {
				box-sizing: border-box;
			}
			body {
				background: var(--bg);
				color: var(--text-primary);
				font-family: var(--font-sans);
				margin: 0;
				padding: 0;
				transition: all var(--animation-normal);
				-webkit-font-smoothing: antialiased;
				-moz-osx-font-smoothing: grayscale;
				min-height: 100vh;
				position: relative;
			}
			body::before {
				content: '';
				position: fixed;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background: var(--bg);
				z-index: -2;
			}
			body::after {
				content: '';
				position: fixed;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background: 
					radial-gradient(circle at 20% 20%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
					radial-gradient(circle at 80% 80%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
					radial-gradient(circle at 40% 60%, rgba(16, 185, 129, 0.05) 0%, transparent 50%);
				z-index: -1;
				pointer-events: none;
			}
			.layout {
				display: flex;
				min-height: 100vh;
				backdrop-filter: blur(20px);
				-webkit-backdrop-filter: blur(20px);
				position: relative;
				z-index: 1;
			}
			.sidebar {
				width: 320px;
				background: var(--sidebar-bg);
				backdrop-filter: blur(30px);
				-webkit-backdrop-filter: blur(30px);
				padding: 2.5rem 2rem;
				border-right: 1px solid var(--border-color);
				display: flex;
				flex-direction: column;
				transition: all var(--animation-normal);
				position: relative;
				overflow: hidden;
			}
			.sidebar::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background: linear-gradient(135deg, transparent 0%, rgba(99, 102, 241, 0.03) 100%);
				pointer-events: none;
			}
			.sidebar-header {
				display: flex;
				align-items: center;
				gap: 1.25rem;
				margin-bottom: 2.5rem;
				position: relative;
				z-index: 2;
			}
			.sidebar-header .logo {
				width: 3.5rem;
				height: 3.5rem;
				background: var(--accent-color);
				border-radius: 1.25rem;
				display: flex;
				align-items: center;
				justify-content: center;
				box-shadow: 
					0 8px 32px var(--glow-color),
					0 4px 16px rgba(0, 0, 0, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.2);
				position: relative;
				overflow: hidden;
				transition: all var(--animation-normal);
			}
			.sidebar-header .logo::before {
				content: '';
				position: absolute;
				top: -50%;
				left: -50%;
				width: 200%;
				height: 200%;
				background: linear-gradient(45deg, transparent, rgba(255, 255, 255, 0.1), transparent);
				transform: translateX(-100%);
				transition: transform 0.6s ease;
			}
			.sidebar-header .logo:hover::before {
				transform: translateX(100%);
			}
			.sidebar-header .logo:hover {
				transform: translateY(-2px) scale(1.05);
				box-shadow: 
					0 12px 40px var(--glow-color),
					0 8px 24px rgba(0, 0, 0, 0.15),
					inset 0 1px 0 rgba(255, 255, 255, 0.3);
			}
			.sidebar-header .logo svg {
				width: 1.75rem;
				height: 1.75rem;
				color: white;
				position: relative;
				z-index: 1;
				filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.2));
			}
			.sidebar-header h1 {
				font-size: 1.625rem;
				font-weight: 700;
				margin: 0;
				letter-spacing: -0.025em;
				background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-muted) 100%);
				-webkit-background-clip: text;
				-webkit-text-fill-color: transparent;
				background-clip: text;
			}
			.status-section {
				background: var(--card-bg);
				backdrop-filter: blur(30px);
				-webkit-backdrop-filter: blur(30px);
				border-radius: 1.5rem;
				padding: 2rem;
				border: 1px solid var(--border-color);
				box-shadow: 
					0 8px 32px var(--shadow-color),
					0 1px 0 rgba(255, 255, 255, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
				margin-bottom: 2.5rem;
				position: relative;
				overflow: hidden;
				transition: all var(--animation-normal);
			}
			.status-section::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 2px;
				background: var(--success-color);
				opacity: 0.8;
			}
			.status-section:hover {
				transform: translateY(-2px);
				box-shadow: 
					0 12px 40px var(--shadow-color),
					0 4px 16px rgba(0, 0, 0, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.2);
			}
			.status-header {
				display: flex;
				align-items: center;
				gap: 1rem;
				margin-bottom: 1.25rem;
			}
			.status-indicator {
				width: 0.875rem;
				height: 0.875rem;
				background: var(--success-color);
				border-radius: 50%;
				box-shadow: 
					0 0 0 4px rgba(16, 185, 129, 0.2),
					0 0 16px rgba(16, 185, 129, 0.4);
				animation: pulse 2s infinite, glow 3s infinite alternate;
				position: relative;
			}
			.status-indicator::before {
				content: '';
				position: absolute;
				top: 50%;
				left: 50%;
				width: 150%;
				height: 150%;
				background: radial-gradient(circle, rgba(16, 185, 129, 0.3) 0%, transparent 70%);
				border-radius: 50%;
				transform: translate(-50%, -50%);
				animation: ripple 2s infinite;
			}
			@keyframes pulse {
				0%, 100% { opacity: 1; transform: scale(1); }
				50% { opacity: 0.8; transform: scale(1.05); }
			}
			@keyframes glow {
				0% { box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.2), 0 0 16px rgba(16, 185, 129, 0.4); }
				100% { box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.4), 0 0 24px rgba(16, 185, 129, 0.6); }
			}
			@keyframes ripple {
				0% { transform: translate(-50%, -50%) scale(0.8); opacity: 1; }
				100% { transform: translate(-50%, -50%) scale(1.5); opacity: 0; }
			}
			@keyframes float {
				0%, 100% { transform: translateY(0px); }
				50% { transform: translateY(-10px); }
			}
			@keyframes shimmer {
				0% { background-position: -200% 0; }
				100% { background-position: 200% 0; }
			}
			.status-title {
				font-weight: 700;
				font-size: 1.125rem;
				background: linear-gradient(135deg, var(--text-primary) 0%, #10b981 100%);
				-webkit-background-clip: text;
				-webkit-text-fill-color: transparent;
				background-clip: text;
			}
			.status-description {
				font-size: 0.9375rem;
				color: var(--text-muted);
				line-height: 1.6;
				margin: 0;
			}
			.theme-toggle {
				margin-top: auto;
				background: var(--card-bg);
				backdrop-filter: blur(30px);
				-webkit-backdrop-filter: blur(30px);
				border: 1px solid var(--border-color);
				border-radius: 1.25rem;
				padding: 1rem;
				cursor: pointer;
				display: flex;
				align-items: center;
				justify-content: center;
				transition: all var(--animation-normal);
				box-shadow: 
					0 4px 16px var(--shadow-color),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
				position: relative;
				overflow: hidden;
			}
			.theme-toggle::before {
				content: '';
				position: absolute;
				top: 0;
				left: -100%;
				width: 100%;
				height: 100%;
				background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
				transition: left 0.5s ease;
			}
			.theme-toggle:hover::before {
				left: 100%;
			}
			.theme-toggle:hover {
				transform: translateY(-2px) scale(1.02);
				box-shadow: 
					0 8px 24px var(--shadow-color),
					0 4px 12px rgba(0, 0, 0, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.2);
				border-color: var(--glow-color);
			}
			.theme-toggle:active {
				transform: translateY(0) scale(0.98);
			}
			.theme-toggle svg {
				width: 1.5rem;
				height: 1.5rem;
				color: var(--text-muted);
				transition: all var(--animation-normal);
				position: relative;
				z-index: 1;
			}
			.theme-toggle:hover svg {
				color: var(--text-primary);
				transform: rotate(15deg) scale(1.1);
			}
			.sun-icon { 
				display: none; 
				animation: rotate 20s linear infinite;
			}
			.moon-icon { 
				display: block;
				animation: float 3s ease-in-out infinite;
			}
			html.dark .sun-icon { 
				display: block;
				animation: rotate 20s linear infinite;
			}
			html.dark .moon-icon { 
				display: none; 
			}
			@keyframes rotate {
				from { transform: rotate(0deg); }
				to { transform: rotate(360deg); }
			}
			.main-content {
				flex: 1;
				padding: 2.5rem;
				overflow-y: auto;
				position: relative;
			}
			.main-content::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background: 
					radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.05) 0%, transparent 50%),
					radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.05) 0%, transparent 50%);
				pointer-events: none;
				z-index: -1;
			}
			.main-header {
				margin-bottom: 3rem;
				position: relative;
				z-index: 2;
			}
			.main-header h2 {
				font-size: 2.75rem;
				font-weight: 800;
				margin: 0 0 1rem 0;
				letter-spacing: -0.03em;
				background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-muted) 100%);
				-webkit-background-clip: text;
				-webkit-text-fill-color: transparent;
				background-clip: text;
				position: relative;
			}
			.main-header h2::after {
				content: '';
				position: absolute;
				bottom: -8px;
				left: 0;
				width: 80px;
				height: 4px;
				background: var(--accent-color);
				border-radius: 2px;
				opacity: 0.8;
			}
			.main-header p {
				font-size: 1.25rem;
				color: var(--text-muted);
				margin: 0;
				font-weight: 400;
				line-height: 1.6;
			}
			.grid-container {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
				gap: 2rem;
				position: relative;
				z-index: 2;
			}
			.card {
				background: var(--card-bg);
				backdrop-filter: blur(30px);
				-webkit-backdrop-filter: blur(30px);
				border-radius: 1.5rem;
				border: 1px solid var(--border-color);
				padding: 2.25rem;
				box-shadow: 
					0 8px 32px var(--shadow-color),
					0 1px 0 rgba(255, 255, 255, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
				transition: all var(--animation-normal);
				position: relative;
				overflow: hidden;
				transform: translateY(0);
			}
			.card::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background: linear-gradient(135deg, transparent 0%, rgba(99, 102, 241, 0.02) 100%);
				pointer-events: none;
				transition: opacity var(--animation-normal);
				opacity: 0;
			}
			.card:hover::before {
				opacity: 1;
			}
			.card:hover {
				transform: translateY(-8px) scale(1.02);
				box-shadow: 
					0 20px 60px var(--shadow-color),
					0 8px 24px rgba(0, 0, 0, 0.1),
					0 1px 0 rgba(255, 255, 255, 0.2),
					inset 0 1px 0 rgba(255, 255, 255, 0.2);
				border-color: var(--glow-color);
			}
			.card:active {
				transform: translateY(-4px) scale(1.01);
			}
			.card-header {
				margin-bottom: 1.75rem;
				position: relative;
				z-index: 2;
			}
			.card-title {
				font-size: 1.375rem;
				font-weight: 700;
				margin: 0 0 0.75rem 0;
				letter-spacing: -0.02em;
				background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-muted) 100%);
				-webkit-background-clip: text;
				-webkit-text-fill-color: transparent;
				background-clip: text;
			}
			.card-description {
				font-size: 1rem;
				color: var(--text-muted);
				margin: 0;
				line-height: 1.6;
				font-weight: 400;
			}
			.input-group {
				display: flex;
				margin-bottom: 1.5rem;
				border-radius: 1rem;
				overflow: hidden;
				box-shadow: 
					0 4px 16px rgba(0, 0, 0, 0.08),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
				position: relative;
				z-index: 2;
			}
			.form-control {
				flex: 1;
				background: rgba(255, 255, 255, 0.08);
				border: 1px solid var(--border-color);
				border-right: none;
				padding: 1.125rem 1.25rem;
				font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', 'JetBrains Mono', Consolas, 'Courier New', monospace;
				font-size: 0.9375rem;
				color: var(--text-primary);
				outline: none;
				transition: all var(--animation-normal);
				font-weight: 500;
				letter-spacing: 0.02em;
			}
			.form-control:focus {
				background: rgba(255, 255, 255, 0.12);
				border-color: var(--accent-color);
				box-shadow: 
					0 0 0 4px rgba(99, 102, 241, 0.15),
					0 4px 16px rgba(99, 102, 241, 0.2);
				transform: translateY(-1px);
			}
			.form-control::selection {
				background: rgba(99, 102, 241, 0.3);
			}
			.btn {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				gap: 0.75rem;
				padding: 1.125rem 1.75rem;
				font-size: 1rem;
				font-weight: 600;
				cursor: pointer;
				border: none;
				background: var(--accent-color);
				color: white;
				transition: all var(--animation-normal);
				outline: none;
				position: relative;
				overflow: hidden;
				text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
				box-shadow: 
					0 4px 16px rgba(99, 102, 241, 0.3),
					inset 0 1px 0 rgba(255, 255, 255, 0.2);
			}
			.btn::before {
				content: '';
				position: absolute;
				top: 0;
				left: -100%;
				width: 100%;
				height: 100%;
				background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
				transition: left 0.5s ease;
			}
			.btn:hover::before {
				left: 100%;
			}
			.btn:hover {
				background: var(--accent-hover);
				transform: translateY(-2px) scale(1.02);
				box-shadow: 
					0 8px 24px rgba(99, 102, 241, 0.4),
					0 4px 12px rgba(0, 0, 0, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.3);
			}
			.btn:active {
				transform: translateY(0) scale(0.98);
			}
			.btn-secondary {
				background: rgba(99, 102, 241, 0.1);
				color: transparent;
				background-clip: text;
				-webkit-background-clip: text;
				background-image: var(--accent-color);
				border: 1px solid rgba(99, 102, 241, 0.2);
				box-shadow: 
					0 4px 16px rgba(99, 102, 241, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
			}
			.btn-secondary:hover {
				background: rgba(99, 102, 241, 0.15);
				border-color: rgba(99, 102, 241, 0.4);
				box-shadow: 
					0 8px 24px rgba(99, 102, 241, 0.2),
					0 4px 12px rgba(0, 0, 0, 0.05),
					inset 0 1px 0 rgba(255, 255, 255, 0.2);
			}
			.card-actions {
				display: flex;
				gap: 1rem;
				position: relative;
				z-index: 2;
			}
			.btn-full {
				flex: 1;
				border-radius: 1rem;
			}
			.info-card {
				grid-column: 1 / -1;
				background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(139, 92, 246, 0.08) 100%);
				border: 1px solid rgba(99, 102, 241, 0.2);
				position: relative;
			}
			.info-card::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 3px;
				background: var(--accent-color);
				border-radius: 1.5rem 1.5rem 0 0;
			}
			.modal {
				position: fixed;
				inset: 0;
				background: rgba(0, 0, 0, 0.6);
				backdrop-filter: blur(20px);
				-webkit-backdrop-filter: blur(20px);
				display: flex;
				align-items: center;
				justify-content: center;
				opacity: 0;
				visibility: hidden;
				transition: all var(--animation-normal);
				z-index: 1000;
			}
			.modal.show {
				opacity: 1;
				visibility: visible;
			}
			.modal-content {
				background: var(--card-bg);
				backdrop-filter: blur(30px);
				-webkit-backdrop-filter: blur(30px);
				padding: 2.5rem;
				border-radius: 2rem;
				border: 1px solid var(--border-color);
				text-align: center;
				transform: scale(0.8) translateY(20px);
				transition: all var(--animation-normal);
				max-width: 400px;
				width: 90%;
				box-shadow: 
					0 25px 50px rgba(0, 0, 0, 0.3),
					0 10px 30px rgba(0, 0, 0, 0.2),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
				position: relative;
				overflow: hidden;
			}
			.modal-content::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background: linear-gradient(135deg, transparent 0%, rgba(99, 102, 241, 0.03) 100%);
				pointer-events: none;
			}
			.modal.show .modal-content {
				transform: scale(1) translateY(0);
			}
			.modal-content h3 {
				margin: 0 0 1rem 0;
				font-size: 1.5rem;
				font-weight: 700;
				background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-muted) 100%);
				-webkit-background-clip: text;
				-webkit-text-fill-color: transparent;
				background-clip: text;
				position: relative;
				z-index: 2;
			}
			.modal-content p {
				margin: 0 0 2rem 0;
				color: var(--text-muted);
				font-size: 1rem;
				line-height: 1.6;
				position: relative;
				z-index: 2;
			}
			.modal-content #qrcode-canvas {
				margin: 0 auto 2rem;
				background: white;
				border-radius: 1.5rem;
				display: inline-block;
				box-shadow: 
					0 8px 32px rgba(0, 0, 0, 0.2),
					0 4px 16px rgba(0, 0, 0, 0.1);
				position: relative;
				z-index: 2;
				overflow: hidden;
			}
			.toast {
				position: fixed;
				bottom: -100px;
				left: 50%;
				transform: translateX(-50%);
				background: var(--card-bg);
				backdrop-filter: blur(30px);
				-webkit-backdrop-filter: blur(30px);
				color: var(--text-primary);
				padding: 1.25rem 2rem;
				border-radius: 1.5rem;
				box-shadow: 
					0 20px 40px var(--shadow-color),
					0 8px 24px rgba(0, 0, 0, 0.1),
					inset 0 1px 0 rgba(255, 255, 255, 0.1);
				opacity: 0;
				transition: all var(--animation-slow);
				z-index: 1001;
				font-weight: 600;
				border: 1px solid var(--border-color);
				position: relative;
				overflow: hidden;
			}
			.toast::before {
				content: '';
				position: absolute;
				top: 0;
				left: 0;
				width: 100%;
				height: 3px;
				background: var(--success-color);
			}
			.toast.show {
				opacity: 1;
				bottom: 2rem;
			}
			@media (max-width: 768px) {
				.layout {
					flex-direction: column;
				}
				.sidebar {
					width: 100%;
					border-right: none;
					border-bottom: 1px solid var(--border-color);
					padding: 2rem 1.5rem;
				}
				.sidebar-header {
					margin-bottom: 2rem;
				}
				.status-section {
					margin-bottom: 2rem;
				}
				.main-content {
					padding: 2rem 1.5rem;
				}
				.main-header h2 {
					font-size: 2.25rem;
				}
				.grid-container {
					grid-template-columns: 1fr;
					gap: 1.5rem;
				}
				.card {
					padding: 2rem;
				}
				.modal-content {
					padding: 2rem;
					max-width: 340px;
				}
			}
			@media (max-width: 480px) {
				.sidebar {
					padding: 1.5rem 1rem;
				}
				.main-content {
					padding: 1.5rem 1rem;
				}
				.main-header h2 {
					font-size: 2rem;
				}
				.card {
					padding: 1.5rem;
				}
				.btn {
					padding: 1rem 1.5rem;
					font-size: 0.9375rem;
				}
				.form-control {
					padding: 1rem;
					font-size: 0.875rem;
				}
			}
		</style>
	</head>
	<body>
		<div class="layout">
			<aside class="sidebar">
				<div class="sidebar-header">
					<div class="logo">
						<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
							<path d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25zm4.28 13.404a.75.75 0 01-.28.53l-1.5 1.5a.75.75 0 11-1.06-1.06l.97-.97-1.415-1.414a.75.75 0 010-1.06l3-3a.75.75 0 011.06 0l1.5 1.5a.75.75 0 010 1.06l-1.775 1.774z"/>
						</svg>
					</div>
					<h1>VLESS 配置中心</h1>
				</div>
				
				<div class="status-section">
					<div class="status-header">
						<div class="status-indicator"></div>
						<div class="status-title">系统运行正常</div>
					</div>
					<div class="status-description">
						所有节点均可正常连接<br>
						服务状态良好
					</div>
				</div>
				
				<button class="theme-toggle" id="theme-toggle" title="切换主题">
					<svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
						<path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.106a.75.75 0 010 1.06l-1.591 1.59a.75.75 0 11-1.06-1.06l1.59-1.59a.75.75 0 011.06 0zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5h2.25a.75.75 0 01.75.75zM17.836 17.836a.75.75 0 01-1.06 0l-1.59-1.591a.75.75 0 111.06-1.06l1.59 1.59a.75.75 0 010 1.061zM12 18a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0v-2.25A.75.75 0 0112 18zM7.214 17.836a.75.75 0 010-1.06l1.59-1.59a.75.75 0 011.06 1.06l-1.59 1.59a.75.75 0 01-1.06 0zM6.106 5.106a.75.75 0 011.06 0l1.591 1.59a.75.75 0 01-1.06 1.06l-1.59-1.59a.75.75 0 010-1.06zM3 12a.75.75 0 01.75-.75h2.25a.75.75 0 010 1.5H3.75A.75.75 0 013 12z"/>
					</svg>
					<svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
						<path fill-rule="evenodd" d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 003.463-.69a.75.75 0 01.981.981A10.503 10.503 0 0118 19.5a10.5 10.5 0 01-10.5-10.5c0-1.25.22-2.454.622-3.569a.75.75 0 01.806-.162z" clip-rule="evenodd"/>
					</svg>
				</button>
			</aside>
			
			<main class="main-content">
				<div class="main-header">
					<h2>配置管理</h2>
					<p>管理您的 VLESS 连接配置和订阅链接</p>
				</div>
				
				<div class="grid-container">
					${hostName.includes("workers.dev") ? `
					<div class="card">
						<div class="card-header">
							<h3 class="card-title">VLESS + WS (无 TLS)</h3>
							<p class="card-description">非加密连接，适用于特殊网络环境</p>
						</div>
						<div class="input-group">
							<input type="text" class="form-control" value="${wVlessws}" readonly>
							<button class="btn" onclick="App.copyToClipboard('${wVlessws}')">复制</button>
						</div>
						<div class="card-actions">
							<button class="btn btn-secondary btn-full" onclick="App.showQrCode('${wVlessws}', 'VLESS + WS (无 TLS)')">显示二维码</button>
						</div>
					</div>` : ''}
					
					<div class="card">
						<div class="card-header">
							<h3 class="card-title">VLESS + WS + TLS</h3>
							<p class="card-description">标准加密连接，推荐日常使用</p>
						</div>
						<div class="input-group">
							<input type="text" class="form-control" value="${pVlesswstls}" readonly>
							<button class="btn" onclick="App.copyToClipboard('${pVlesswstls}')">复制</button>
						</div>
						<div class="card-actions">
							<button class="btn btn-secondary btn-full" onclick="App.showQrCode('${pVlesswstls}', 'VLESS + WS + TLS')">显示二维码</button>
						</div>
					</div>
					
					<div class="card">
						<div class="card-header">
							<h3 class="card-title">通用订阅链接</h3>
							<p class="card-description">适用于 v2ray、NekoBox 等客户端</p>
						</div>
						<div class="input-group">
							<input type="text" class="form-control" value="${hostName.includes("workers.dev") ? ty : pty}" readonly>
							<button class="btn" onclick="App.copyToClipboard('${hostName.includes("workers.dev") ? ty : pty}')">复制</button>
						</div>
					</div>
					
					<div class="card">
						<div class="card-header">
							<h3 class="card-title">Clash Meta 订阅</h3>
							<p class="card-description">适用于 Clash Meta 内核客户端</p>
						</div>
						<div class="input-group">
							<input type="text" class="form-control" value="${hostName.includes("workers.dev") ? cl : pcl}" readonly>
							<button class="btn" onclick="App.copyToClipboard('${hostName.includes("workers.dev") ? cl : pcl}')">复制</button>
						</div>
					</div>
					
					<div class="card">
						<div class="card-header">
							<h3 class="card-title">Sing-Box 订阅</h3>
							<p class="card-description">适用于 Sing-Box 内核客户端</p>
						</div>
						<div class="input-group">
							<input type="text" class="form-control" value="${hostName.includes("workers.dev") ? sb : psb}" readonly>
							<button class="btn" onclick="App.copyToClipboard('${hostName.includes("workers.dev") ? sb : psb}')">复制</button>
						</div>
					</div>
					
					<div class="card">
						<div class="card-header">
							<h3 class="card-title">聚合分享链接</h3>
							<p class="card-description">包含所有节点配置，一键导入</p>
						</div>
						<div class="card-actions">
							<button class="btn btn-full" onclick="App.copyToClipboard('${hostName.includes("workers.dev") ? wkShare : pgShare}')">复制聚合链接</button>
							<button class="btn btn-secondary btn-full" onclick="App.showQrCode('${hostName.includes("workers.dev") ? wkShare : pgShare}', '聚合分享链接')">显示二维码</button>
						</div>
					</div>
					
					<div class="card info-card">
						<div class="card-header">
							<h3 class="card-title">使用说明</h3>
						</div>
						<div style="font-size: 0.9375rem; color: var(--text-muted); line-height: 1.6;">
							${note.replace(/\n/g, '<br>')}
						</div>
						<div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-color); font-size: 0.875rem; color: var(--text-muted);">
							Proxy Script Version: V25.5.27
						</div>
					</div>
				</div>
			</main>
		</div>

		<div id="modal" class="modal">
			<div class="modal-content" onclick="event.stopPropagation()">
				<h3 id="modal-title"></h3>
				<p>请使用兼容的客户端扫描二维码</p>
				<canvas id="qrcode-canvas"></canvas>
				<button class="btn btn-full" onclick="App.closeModal()">关闭</button>
			</div>
		</div>
		
		<div id="toast" class="toast"></div>

		<script>
			const App = {
				init() {
					this.theme.init();
					this.modal.init();
					this.bindEvents();
				},
				
				bindEvents() {
					document.getElementById('modal').addEventListener('click', () => this.modal.close());
				},

				theme: {
					init() {
						this.toggleBtn = document.getElementById('theme-toggle');
						this.prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
						this.toggleBtn.addEventListener('click', () => this.toggle());
						this.apply(localStorage.getItem('theme') || (this.prefersDark.matches ? 'dark' : 'light'));
						this.prefersDark.addEventListener('change', (e) => {
							if (!localStorage.getItem('theme')) this.apply(e.matches ? 'dark' : 'light');
						});
					},
					apply(theme) {
						if (theme === 'dark') document.documentElement.classList.add('dark');
						else document.documentElement.classList.remove('dark');
					},
					toggle() {
						const newTheme = document.documentElement.classList.contains('dark') ? 'light' : 'dark';
						localStorage.setItem('theme', newTheme);
						this.apply(newTheme);
					}
				},

				toast: {
					show(message) {
						const toastEl = document.getElementById('toast');
						toastEl.textContent = message;
						toastEl.classList.add('show');
						setTimeout(() => toastEl.classList.remove('show'), 2500);
					}
				},

				copyToClipboard(text) {
					navigator.clipboard.writeText(text).then(() => {
						this.toast.show('已复制到剪贴板！');
					}).catch(err => {
						console.error('无法复制: ', err);
						this.toast.show('复制失败！');
					});
				},

				modal: {
					init() {
						this.modalEl = document.getElementById('modal');
						this.titleEl = document.getElementById('modal-title');
						this.qrCanvas = document.getElementById('qrcode-canvas');
					},
					show(data, title) {
						this.titleEl.textContent = title;
						new QRious({
							element: this.qrCanvas,
							value: data,
							size: 256,
							padding: 16,
							background: 'white',
							foreground: 'black',
						});
						this.modalEl.classList.add('show');
					},
					close() {
						this.modalEl.classList.remove('show');
					}
				},

				showQrCode(data, title) {
					this.modal.show(data, title);
				},

				closeModal() {
					this.modal.close();
				}
			};

			document.addEventListener('DOMContentLoaded', () => App.init());
		</script>
	</body>
	</html>`;

	return displayHtml;
}

function gettyConfig(userID, hostName) {
	const vlessshare = btoa(`vless://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
	return `${vlessshare}`
}

function getclConfig(userID, hostName) {
	return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V1_${IP1}_${PT1}
  type: vless
  server: ${IP1.replace(/[\[\]]/g, '')}
  port: ${PT1}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V2_${IP2}_${PT2}
  type: vless
  server: ${IP2.replace(/[\[\]]/g, '')}
  port: ${PT2}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V3_${IP3}_${PT3}
  type: vless
  server: ${IP3.replace(/[\[\]]/g, '')}
  port: ${PT3}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V4_${IP4}_${PT4}
  type: vless
  server: ${IP4.replace(/[\[\]]/g, '')}
  port: ${PT4}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V5_${IP5}_${PT5}
  type: vless
  server: ${IP5.replace(/[\[\]]/g, '')}
  port: ${PT5}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V6_${IP6}_${PT6}
  type: vless
  server: ${IP6.replace(/[\[\]]/g, '')}
  port: ${PT6}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V7_${IP7}_${PT7}
  type: vless
  server: ${IP7.replace(/[\[\]]/g, '')}
  port: ${PT7}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}

function getsbConfig(userID, hostName) {
	return `{
	  "log": {
		"disabled": false,
		"level": "info",
		"timestamp": true
	  },
	  "experimental": {
		"clash_api": {
		  "external_controller": "127.0.0.1:9090",
		  "external_ui": "ui",
		  "external_ui_download_url": "",
		  "external_ui_download_detour": "",
		  "secret": "",
		  "default_mode": "Rule"
		},
		"cache_file": {
		  "enabled": true,
		  "path": "cache.db",
		  "store_fakeip": true
		}
	  },
	  "dns": {
		"servers": [
		  {
			"tag": "proxydns",
			"address": "tls://8.8.8.8/dns-query",
			"detour": "select"
		  },
		  {
			"tag": "localdns",
			"address": "h3://223.5.5.5/dns-query",
			"detour": "direct"
		  },
		  {
			"tag": "dns_fakeip",
			"address": "fakeip"
		  }
		],
		"rules": [
		  {
			"outbound": "any",
			"server": "localdns",
			"disable_cache": true
		  },
		  {
			"clash_mode": "Global",
			"server": "proxydns"
		  },
		  {
			"clash_mode": "Direct",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-cn",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"server": "proxydns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"query_type": [
			  "A",
			  "AAAA"
			],
			"server": "dns_fakeip"
		  }
		],
		"fakeip": {
		  "enabled": true,
		  "inet4_range": "198.18.0.0/15",
		  "inet6_range": "fc00::/18"
		},
		"independent_cache": true,
		"final": "proxydns"
	  },
	  "inbounds": [
		{
		  "type": "tun",
		  "tag": "tun-in",
		  "address": [
			"172.19.0.1/30",
			"fd00::1/126"
		  ],
		  "auto_route": true,
		  "strict_route": true,
		  "sniff": true,
		  "sniff_override_destination": true,
		  "domain_strategy": "prefer_ipv4"
		}
	  ],
	  "outbounds": [
		{
		  "tag": "select",
		  "type": "selector",
		  "default": "auto",
		  "outbounds": [
			"auto",
			"CF_V1_${IP1}_${PT1}",
			"CF_V2_${IP2}_${PT2}",
			"CF_V3_${IP3}_${PT3}",
			"CF_V4_${IP4}_${PT4}",
			"CF_V5_${IP5}_${PT5}",
			"CF_V6_${IP6}_${PT6}",
			"CF_V7_${IP7}_${PT7}",
			"CF_V8_${IP8}_${PT8}",
			"CF_V9_${IP9}_${PT9}",
			"CF_V10_${IP10}_${PT10}",
			"CF_V11_${IP11}_${PT11}",
			"CF_V12_${IP12}_${PT12}",
			"CF_V13_${IP13}_${PT13}"
		  ]
		},
		{
		  "server": "${IP1}",
		  "server_port": ${PT1},
		  "tag": "CF_V1_${IP1}_${PT1}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP2}",
		  "server_port": ${PT2},
		  "tag": "CF_V2_${IP2}_${PT2}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP3}",
		  "server_port": ${PT3},
		  "tag": "CF_V3_${IP3}_${PT3}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP4}",
		  "server_port": ${PT4},
		  "tag": "CF_V4_${IP4}_${PT4}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP5}",
		  "server_port": ${PT5},
		  "tag": "CF_V5_${IP5}_${PT5}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP6}",
		  "server_port": ${PT6},
		  "tag": "CF_V6_${IP6}_${PT6}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP7}",
		  "server_port": ${PT7},
		  "tag": "CF_V7_${IP7}_${PT7}",
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP8}",
		  "server_port": ${PT8},
		  "tag": "CF_V8_${IP8}_${PT8}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP9}",
		  "server_port": ${PT9},
		  "tag": "CF_V9_${IP9}_${PT9}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP10}",
		  "server_port": ${PT10},
		  "tag": "CF_V10_${IP10}_${PT10}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP11}",
		  "server_port": ${PT11},
		  "tag": "CF_V11_${IP11}_${PT11}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP12}",
		  "server_port": ${PT12},
		  "tag": "CF_V12_${IP12}_${PT12}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP13}",
		  "server_port": ${PT13},
		  "tag": "CF_V13_${IP13}_${PT13}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "tag": "direct",
		  "type": "direct"
		},
		{
		  "tag": "auto",
		  "type": "urltest",
		  "outbounds": [
			"CF_V1_${IP1}_${PT1}",
			"CF_V2_${IP2}_${PT2}",
			"CF_V3_${IP3}_${PT3}",
			"CF_V4_${IP4}_${PT4}",
			"CF_V5_${IP5}_${PT5}",
			"CF_V6_${IP6}_${PT6}",
			"CF_V7_${IP7}_${PT7}",
			"CF_V8_${IP8}_${PT8}",
			"CF_V9_${IP9}_${PT9}",
			"CF_V10_${IP10}_${PT10}",
			"CF_V11_${IP11}_${PT11}",
			"CF_V12_${IP12}_${PT12}",
			"CF_V13_${IP13}_${PT13}"
		  ],
		  "url": "https://www.gstatic.com/generate_204",
		  "interval": "1m",
		  "tolerance": 50,
		  "interrupt_exist_connections": false
		}
	  ],
	  "route": {
		"rule_set": [
		  {
			"tag": "geosite-geolocation-!cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geosite-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geoip-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  }
		],
		"auto_detect_interface": true,
		"final": "select",
		"rules": [
		  {
			"inbound": "tun-in",
			"action": "sniff"
		  },
		  {
			"protocol": "dns",
			"action": "hijack-dns"
		  },
		  {
			"port": 443,
			"network": "udp",
			"action": "reject"
		  },
		  {
			"clash_mode": "Direct",
			"outbound": "direct"
		  },
		  {
			"clash_mode": "Global",
			"outbound": "select"
		  },
		  {
			"rule_set": "geoip-cn",
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-cn",
			"outbound": "direct"
		  },
		  {
			"ip_is_private": true,
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"outbound": "select"
		  }
		]
	  },
	  "ntp": {
		"enabled": true,
		"server": "time.apple.com",
		"server_port": 123,
		"interval": "30m",
		"detour": "direct"
	  }
	}`
}

function getptyConfig(userID, hostName) {
	const vlessshare = btoa(`vless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
	return `${vlessshare}`
}

function getpclConfig(userID, hostName) {
	return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}

function getpsbConfig(userID, hostName) {
	return `{
		  "log": {
			"disabled": false,
			"level": "info",
			"timestamp": true
		  },
		  "experimental": {
			"clash_api": {
			  "external_controller": "127.0.0.1:9090",
			  "external_ui": "ui",
			  "external_ui_download_url": "",
			  "external_ui_download_detour": "",
			  "secret": "",
			  "default_mode": "Rule"
			},
			"cache_file": {
			  "enabled": true,
			  "path": "cache.db",
			  "store_fakeip": true
			}
		  },
		  "dns": {
			"servers": [
			  {
				"tag": "proxydns",
				"address": "tls://8.8.8.8/dns-query",
				"detour": "select"
			  },
			  {
				"tag": "localdns",
				"address": "h3://223.5.5.5/dns-query",
				"detour": "direct"
			  },
			  {
				"tag": "dns_fakeip",
				"address": "fakeip"
			  }
			],
			"rules": [
			  {
				"outbound": "any",
				"server": "localdns",
				"disable_cache": true
			  },
			  {
				"clash_mode": "Global",
				"server": "proxydns"
			  },
			  {
				"clash_mode": "Direct",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-cn",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"server": "proxydns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"query_type": [
				  "A",
				  "AAAA"
				],
				"server": "dns_fakeip"
			  }
			],
			"fakeip": {
			  "enabled": true,
			  "inet4_range": "198.18.0.0/15",
			  "inet6_range": "fc00::/18"
			},
			"independent_cache": true,
			"final": "proxydns"
		  },
		  "inbounds": [
			{
			  "type": "tun",
			  "tag": "tun-in",
			  "address": [
				"172.19.0.1/30",
				"fd00::1/126"
			  ],
			  "auto_route": true,
			  "strict_route": true,
			  "sniff": true,
			  "sniff_override_destination": true,
			  "domain_strategy": "prefer_ipv4"
			}
		  ],
		  "outbounds": [
			{
			  "tag": "select",
			  "type": "selector",
			  "default": "auto",
			  "outbounds": [
				"auto",
				"CF_V8_${IP8}_${PT8}",
				"CF_V9_${IP9}_${PT9}",
				"CF_V10_${IP10}_${PT10}",
				"CF_V11_${IP11}_${PT11}",
				"CF_V12_${IP12}_${PT12}",
				"CF_V13_${IP13}_${PT13}"
			  ]
			},
			{
			  "server": "${IP8}",
			  "server_port": ${PT8},
			  "tag": "CF_V8_${IP8}_${PT8}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP9}",
			  "server_port": ${PT9},
			  "tag": "CF_V9_${IP9}_${PT9}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP10}",
			  "server_port": ${PT10},
			  "tag": "CF_V10_${IP10}_${PT10}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP11}",
			  "server_port": ${PT11},
			  "tag": "CF_V11_${IP11}_${PT11}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP12}",
			  "server_port": ${PT12},
			  "tag": "CF_V12_${IP12}_${PT12}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP13}",
			  "server_port": ${PT13},
			  "tag": "CF_V13_${IP13}_${PT13}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "tag": "direct",
			  "type": "direct"
			},
			{
			  "tag": "auto",
			  "type": "urltest",
			  "outbounds": [
				"CF_V8_${IP8}_${PT8}",
				"CF_V9_${IP9}_${PT9}",
				"CF_V10_${IP10}_${PT10}",
				"CF_V11_${IP11}_${PT11}",
				"CF_V12_${IP12}_${PT12}",
				"CF_V13_${IP13}_${PT13}"
			  ],
			  "url": "https://www.gstatic.com/generate_204",
			  "interval": "1m",
			  "tolerance": 50,
			  "interrupt_exist_connections": false
			}
		  ],
		  "route": {
			"rule_set": [
			  {
				"tag": "geosite-geolocation-!cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geosite-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geoip-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  }
			],
			"auto_detect_interface": true,
			"final": "select",
			"rules": [
			  {
				"inbound": "tun-in",
				"action": "sniff"
			  },
			  {
				"protocol": "dns",
				"action": "hijack-dns"
			  },
			  {
				"port": 443,
				"network": "udp",
				"action": "reject"
			  },
			  {
				"clash_mode": "Direct",
				"outbound": "direct"
			  },
			  {
				"clash_mode": "Global",
				"outbound": "select"
			  },
			  {
				"rule_set": "geoip-cn",
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-cn",
				"outbound": "direct"
			  },
			  {
				"ip_is_private": true,
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"outbound": "select"
			  }
			]
		  },
		  "ntp": {
			"enabled": true,
			"server": "time.apple.com",
			"server_port": 123,
			"interval": "30m",
			"detour": "direct"
		  }
		}`;
}
