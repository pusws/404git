//nat64自动填充proxyip，无需且不支持proxyip设置
import { connect } from "cloudflare:sockets";
const WS_READY_STATE_OPEN = 1;
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";
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
						const \u0076\u006c\u0065\u0073\u0073Config = get\u0076\u006c\u0065\u0073\u0073Config(userID, request.headers.get("Host"));
						return new Response(`${\u0076\u006c\u0065\u0073\u0073Config}`, {
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
						// return new Response('Not found', { status: 404 });
						// For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
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
						// Use fetch to proxy the request to 15 different domains
						const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
						let modifiedRequest = new Request(proxyUrl, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: "manual",
						});
						const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
						// Check for 302 or 301 redirect status and return an error response
						if ([301, 302].includes(proxyResponse.status)) {
							return new Response(`Redirects to ${randomHostname} are not allowed.`, {
								status: 403,
								statusText: "Forbidden",
							});
						}
						// Return the response from the proxy server
						return proxyResponse;
				}
			}
			return await handle\u0076\u006c\u0065\u0073\u0073WebSocket(request);
		} catch (err) {
      /** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

async function handle\u0076\u006c\u0065\u0073\u0073WebSocket(request) {
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

			const result = parse\u0076\u006c\u0065\u0073\u0073Header(chunk, userID);
			if (result.hasError) {
				throw new Error(result.message);
			}

			const \u0076\u006c\u0065\u0073\u0073RespHeader = new Uint8Array([result.\u0076\u006c\u0065\u0073\u0073Version[0], 0]);
			const rawClientData = chunk.slice(result.rawDataIndex);

			if (result.isUDP) {
				if (result.portRemote === 53) {
					isDns = true;
					const { write } = await handleUDPOutBound(serverWS, \u0076\u006c\u0065\u0073\u0073RespHeader);
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
				const prefixes = ['2602:fc59:b0:64::']; //2001:67c:2960:6464::
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

					pipeRemoteToWebSocket(tcpSocket, serverWS, \u0076\u006c\u0065\u0073\u0073RespHeader, null);
				} catch (err) {
					console.error('NAT64 IPv6连接失败:', err);
					serverWS.close(1011, 'NAT64 IPv6连接失败: ' + err.message);
				}
			}

			try {
				const tcpSocket = await connectAndWrite(result.addressRemote, result.portRemote);
				pipeRemoteToWebSocket(tcpSocket, serverWS, \u0076\u006c\u0065\u0073\u0073RespHeader, retry);
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
				} catch (e) {
				}
			}
		}
	});
}

function parse\u0076\u006c\u0065\u0073\u0073Header(buffer, userID) {
	if (buffer.byteLength < 24) {
		return { hasError: true, message: '无效的头部长度' };
	}

	const view = new DataView(buffer);
	const version = new Uint8Array(buffer.slice(0, 1));

	const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
	if (uuid !== userID) {
		return { hasError: true, message: '无效的用户' };
	}

	const optionsLength = view.getUint8(17);
	const command = view.getUint8(18 + optionsLength);

	let isUDP = false;
	if (command === 1) {

	} else if (command === 2) {

		isUDP = true;
	} else {
		return { hasError: true, message: '不支持的命令，仅支持TCP(01)和UDP(02)' };
	}

	let offset = 19 + optionsLength;
	const port = view.getUint16(offset);
	offset += 2;

	const addressType = view.getUint8(offset++);
	let address = '';

	switch (addressType) {
		case 1: // IPv4
			address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
			offset += 4;
			break;

		case 2: // 域名
			const domainLength = view.getUint8(offset++);
			address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
			offset += domainLength;
			break;

		case 3: // IPv6
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
				offset += 2;
			}
			address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
			break;

		default:
			return { hasError: true, message: '不支持的地址类型' };
	}

	return {
		hasError: false,
		addressRemote: address,
		portRemote: port,
		rawDataIndex: offset,
		\u0076\u006c\u0065\u0073\u0073Version: version,
		isUDP
	};
}

function pipeRemoteToWebSocket(remoteSocket, ws, \u0076\u006c\u0065\u0073\u0073Header, retry = null) {
	let headerSent = false;
	let hasIncomingData = false;

	remoteSocket.readable.pipeTo(new WritableStream({
		write(chunk) {
			hasIncomingData = true;
			if (ws.readyState === WS_READY_STATE_OPEN) {
				if (!headerSent) {
					const combined = new Uint8Array(\u0076\u006c\u0065\u0073\u0073Header.byteLength + chunk.byteLength);
					combined.set(new Uint8Array(\u0076\u006c\u0065\u0073\u0073Header), 0);
					combined.set(new Uint8Array(chunk), \u0076\u006c\u0065\u0073\u0073Header.byteLength);
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
		} catch (e) {
		}
	}
}

function formatUUID(bytes) {
	const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function handleUDPOutBound(webSocket, \u0076\u006c\u0065\u0073\u0073ResponseHeader) {
	let is\u0076\u006c\u0065\u0073\u0073HeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {
		},
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
		flush(controller) {
		}
	});

	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch('https://1.1.1.1/dns-query',
				{
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
				if (is\u0076\u006c\u0065\u0073\u0073HeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([\u0076\u006c\u0065\u0073\u0073ResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					is\u0076\u006c\u0065\u0073\u0073HeaderSent = true;
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
 *
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function getvlessConfig(userID, hostName) {
	const wvlessws = `vless://${userID}@${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
	const pvlesswstls = `vless://${userID}@${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
	const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP使用nat64自动生成，无需设置`;
	const ty = `https://${hostName}/${userID}/ty`
	const cl = `https://${hostName}/${userID}/cl`
	const sb = `https://${hostName}/${userID}/sb`
	const pty = `https://${hostName}/${userID}/pty`
	const pcl = `https://${hostName}/${userID}/pcl`
	const psb = `https://${hostName}/${userID}/psb`

	const wkvlessshare = btoa(`vless://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);


	const pgvlessshare = btoa(`vless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);


	const noteshow = note.replace(/\n/g, '<br>');
	const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
:root {
  --ukraine-blue: #005BBB;
  --ukraine-yellow: #FFD700;
  --ukraine-light-blue: #1E88E5;
  --ukraine-light-yellow: #FFF176;
}

body {
  background: linear-gradient(135deg, var(--ukraine-blue) 0%, var(--ukraine-light-blue) 50%, var(--ukraine-yellow) 100%);
  min-height: 100vh;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.main-container {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  border-radius: 20px;
  box-shadow: 0 8px 32px rgba(0, 91, 187, 0.3);
  margin: 20px auto;
  padding: 30px;
  border: 2px solid rgba(255, 215, 0, 0.3);
}

.page-title {
  color: var(--ukraine-blue);
  font-weight: bold;
  text-align: center;
  margin-bottom: 30px;
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
  border-bottom: 3px solid var(--ukraine-yellow);
  padding-bottom: 15px;
}

.section-title {
  color: var(--ukraine-blue);
  border-left: 5px solid var(--ukraine-yellow);
  padding-left: 15px;
  margin: 30px 0 20px 0;
  font-weight: 600;
}

.info-card {
  background: linear-gradient(45deg, rgba(0, 91, 187, 0.05), rgba(255, 215, 0, 0.05));
  border: 2px solid var(--ukraine-yellow);
  border-radius: 15px;
  padding: 20px;
  margin: 15px 0;
  box-shadow: 0 4px 15px rgba(0, 91, 187, 0.1);
  transition: all 0.3s ease;
}

.info-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 8px 25px rgba(0, 91, 187, 0.2);
}

.table-ukraine {
  background: rgba(255, 255, 255, 0.9);
  border-radius: 15px;
  overflow: hidden;
  box-shadow: 0 4px 15px rgba(0, 91, 187, 0.1);
  margin: 20px 0;
}

.table-ukraine thead {
  background: linear-gradient(45deg, var(--ukraine-blue), var(--ukraine-light-blue));
  color: white;
}

.table-ukraine th {
  border: none;
  padding: 15px;
  font-weight: 600;
}

.table-ukraine td {
  border-color: rgba(0, 91, 187, 0.1);
  padding: 15px;
  vertical-align: middle;
}

.btn-ukraine {
  background: linear-gradient(45deg, var(--ukraine-blue), var(--ukraine-light-blue));
  border: 2px solid var(--ukraine-yellow);
  color: white;
  border-radius: 25px;
  padding: 10px 25px;
  font-weight: 600;
  transition: all 0.3s ease;
  text-transform: none;
}

.btn-ukraine:hover {
  background: linear-gradient(45deg, var(--ukraine-light-blue), var(--ukraine-blue));
  transform: translateY(-2px);
  box-shadow: 0 5px 15px rgba(0, 91, 187, 0.3);
  color: white;
}

.btn-ukraine:active {
  transform: translateY(0);
}

.limited-width {
    max-width: 300px;
    overflow: auto;
    word-wrap: break-word;
    font-family: 'Courier New', monospace;
    background: rgba(0, 91, 187, 0.05);
    padding: 10px;
    border-radius: 8px;
    border: 1px solid rgba(255, 215, 0, 0.3);
}

.params-list {
  background: rgba(255, 215, 0, 0.1);
  border-radius: 10px;
  padding: 20px;
  border: 1px solid var(--ukraine-yellow);
}

.params-list li {
  margin: 8px 0;
  padding: 5px 0;
  border-bottom: 1px dotted rgba(0, 91, 187, 0.2);
}

.params-list li:last-child {
  border-bottom: none;
}

.note-section {
  background: linear-gradient(45deg, rgba(255, 215, 0, 0.1), rgba(0, 91, 187, 0.05));
  border: 2px solid var(--ukraine-yellow);
  border-radius: 15px;
  padding: 20px;
  margin: 20px 0;
  box-shadow: 0 4px 15px rgba(255, 215, 0, 0.2);
}

.ukraine-flag {
  display: inline-block;
  width: 30px;
  height: 20px;
  background: linear-gradient(to bottom, var(--ukraine-blue) 50%, var(--ukraine-yellow) 50%);
  border-radius: 3px;
  margin-right: 10px;
  vertical-align: middle;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
}

.copy-success {
  background: linear-gradient(45deg, #28a745, #20c997);
  color: white;
  border: none;
  border-radius: 20px;
  padding: 8px 20px;
  font-size: 14px;
  margin-left: 10px;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: scale(0.8); }
  to { opacity: 1; transform: scale(1); }
}

.divider {
  height: 3px;
  background: linear-gradient(90deg, var(--ukraine-blue), var(--ukraine-yellow), var(--ukraine-blue));
  border-radius: 2px;
  margin: 30px 0;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

@media (max-width: 768px) {
  .main-container {
    margin: 10px;
    padding: 20px;
    border-radius: 15px;
  }
  
  .limited-width {
    max-width: 200px;
  }
}
</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  
  // 显示复制成功提示
  const event = window.event;
  const btn = event.target;
  const originalText = btn.innerHTML;
  btn.innerHTML = '<i class="fas fa-check"></i> 已复制!';
  btn.className = btn.className.replace('btn-ukraine', 'copy-success');
  
  setTimeout(() => {
    btn.innerHTML = originalText;
    btn.className = btn.className.replace('copy-success', 'btn-ukraine');
  }, 2000);
}
</script>
`;
	if (hostName.includes("workers.dev")) {
		return `
${displayHtml}
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-12 col-lg-10">
            <div class="main-container">
                <h1 class="page-title">
                    <span class="ukraine-flag"></span>
                    Cloudflare Workers/Pages VLESS 代理脚本
                    <span class="ukraine-flag"></span>
                    <br><small class="text-muted" style="font-size: 0.6em;">V25.5.27</small>
                </h1>
                
                <div class="note-section">
                    <h5 style="color: var(--ukraine-blue); margin-bottom: 15px;">
                        <i class="fas fa-info-circle"></i> 项目信息
                    </h5>
                    <p>${noteshow}</p>
                </div>
                
                <div class="divider"></div>
                
                <div class="info-card">
                    <h3 class="section-title">
                        <i class="fas fa-link"></i> CF-Workers VLESS+WS 节点
                    </h3>
                    <div class="table-ukraine table-responsive">
                        <table class="table table-borderless">
                            <thead>
                                <tr>
                                    <th><i class="fas fa-star"></i> 节点特色</th>
                                    <th><i class="fas fa-copy"></i> 配置链接</th>
                                    <th><i class="fas fa-tools"></i> 操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td class="limited-width">
                                        <i class="fas fa-shield-alt text-success"></i> 
                                        关闭了TLS加密，无视域名阻断
                                    </td>
                                    <td class="limited-width">${wvlessws}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${wvlessws}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <h5 style="color: var(--ukraine-blue); margin-top: 25px;">
                        <i class="fas fa-cog"></i> 客户端参数
                    </h5>
                    <ul class="params-list">
                        <li><strong>客户端地址(address)：</strong>自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                        <li><strong>端口(port)：</strong>7个http端口可任意选择(80、8080、8880、2052、2082、2086、2095)，或反代IP对应端口</li>
                        <li><strong>用户ID(uuid)：</strong>${userID}</li>
                        <li><strong>传输协议(network)：</strong>ws 或者 websocket</li>
                        <li><strong>伪装域名(host)：</strong>${hostName}</li>
                        <li><strong>路径(path)：</strong>/?ed=2560</li>
                        <li><strong>传输安全(TLS)：</strong>关闭</li>
                    </ul>
                </div>
                
                <div class="divider"></div>
                
                <div class="info-card">
                    <h3 class="section-title">
                        <i class="fas fa-lock"></i> CF-Workers VLESS+WS+TLS 节点
                    </h3>
                    <div class="table-ukraine table-responsive">
                        <table class="table table-borderless">
                            <thead>
                                <tr>
                                    <th><i class="fas fa-star"></i> 节点特色</th>
                                    <th><i class="fas fa-copy"></i> 配置链接</th>
                                    <th><i class="fas fa-tools"></i> 操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td class="limited-width">
                                        <i class="fas fa-lock text-warning"></i> 
                                        启用了TLS加密<br>
                                        <small class="text-muted">如果客户端支持分片(Fragment)功能，建议开启，防止域名阻断</small>
                                    </td>
                                    <td class="limited-width">${pvlesswstls}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${pvlesswstls}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <h5 style="color: var(--ukraine-blue); margin-top: 25px;">
                        <i class="fas fa-cog"></i> 客户端参数
                    </h5>
                    <ul class="params-list">
                        <li><strong>客户端地址(address)：</strong>自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                        <li><strong>端口(port)：</strong>6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                        <li><strong>用户ID(uuid)：</strong>${userID}</li>
                        <li><strong>传输协议(network)：</strong>ws 或者 websocket</li>
                        <li><strong>伪装域名(host)：</strong>${hostName}</li>
                        <li><strong>路径(path)：</strong>/?ed=2560</li>
                        <li><strong>传输安全(TLS)：</strong>开启</li>
                        <li><strong>跳过证书验证(allowlnsecure)：</strong>false</li>
                    </ul>
                </div>
                
                <div class="divider"></div>
                
                <div class="info-card">
                    <h3 class="section-title">
                        <i class="fas fa-rss"></i> 聚合订阅链接
                    </h3>
                    
                    <div class="alert" style="background: rgba(255, 215, 0, 0.1); border: 1px solid var(--ukraine-yellow); color: var(--ukraine-blue);">
                        <h6><i class="fas fa-exclamation-triangle"></i> 注意事项：</h6>
                        <ul class="mb-0">
                            <li>默认每个订阅链接包含TLS+非TLS共13个端口节点</li>
                            <li>当前workers域名作为订阅链接，需通过代理进行订阅更新</li>
                            <li>如使用的客户端不支持分片功能，则TLS节点不可用</li>
                        </ul>
                    </div>
                    
                    <div class="table-ukraine table-responsive">
                        <table class="table table-borderless">
                            <tbody>
                                <tr>
                                    <td style="background: rgba(0, 91, 187, 0.05); font-weight: bold;">
                                        <i class="fas fa-share-alt"></i> 聚合通用分享链接 (可直接导入客户端)
                                    </td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${wkvlessshare}')">
                                            <i class="fas fa-download"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background: rgba(255, 215, 0, 0.05); font-weight: bold;">
                                        <i class="fas fa-link"></i> 聚合通用订阅链接
                                    </td>
                                    <td class="limited-width">${ty}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${ty}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background: rgba(0, 91, 187, 0.05); font-weight: bold;">
                                        <i class="fab fa-cloudflare"></i> Clash-meta订阅链接
                                    </td>
                                    <td class="limited-width">${cl}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${cl}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background: rgba(255, 215, 0, 0.05); font-weight: bold;">
                                        <i class="fas fa-box"></i> Sing-box订阅链接
                                    </td>
                                    <td class="limited-width">${sb}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${sb}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
`;
	} else {
		return `
${displayHtml}
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-12 col-lg-10">
            <div class="main-container">
                <h1 class="page-title">
                    <span class="ukraine-flag"></span>
                    Cloudflare Workers/Pages VLESS 代理脚本
                    <span class="ukraine-flag"></span>
                    <br><small class="text-muted" style="font-size: 0.6em;">V25.5.27</small>
                </h1>
                
                <div class="note-section">
                    <h5 style="color: var(--ukraine-blue); margin-bottom: 15px;">
                        <i class="fas fa-info-circle"></i> 项目信息
                    </h5>
                    <p>${noteshow}</p>
                </div>
                
                <div class="divider"></div>
                
                <div class="info-card">
                    <h3 class="section-title">
                        <i class="fas fa-lock"></i> CF-Pages/Workers/自定义域 VLESS+WS+TLS 节点
                    </h3>
                    <div class="table-ukraine table-responsive">
                        <table class="table table-borderless">
                            <thead>
                                <tr>
                                    <th><i class="fas fa-star"></i> 节点特色</th>
                                    <th><i class="fas fa-copy"></i> 配置链接</th>
                                    <th><i class="fas fa-tools"></i> 操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td class="limited-width">
                                        <i class="fas fa-lock text-success"></i> 
                                        启用了TLS加密<br>
                                        <small class="text-muted">如果客户端支持分片(Fragment)功能，可开启，防止域名阻断</small>
                                    </td>
                                    <td class="limited-width">${pvlesswstls}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${pvlesswstls}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <h5 style="color: var(--ukraine-blue); margin-top: 25px;">
                        <i class="fas fa-cog"></i> 客户端参数
                    </h5>
                    <ul class="params-list">
                        <li><strong>客户端地址(address)：</strong>自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                        <li><strong>端口(port)：</strong>6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                        <li><strong>用户ID(uuid)：</strong>${userID}</li>
                        <li><strong>传输协议(network)：</strong>ws 或者 websocket</li>
                        <li><strong>伪装域名(host)：</strong>${hostName}</li>
                        <li><strong>路径(path)：</strong>/?ed=2560</li>
                        <li><strong>传输安全(TLS)：</strong>开启</li>
                        <li><strong>跳过证书验证(allowlnsecure)：</strong>false</li>
                    </ul>
                </div>
                
                <div class="divider"></div>
                
                <div class="info-card">
                    <h3 class="section-title">
                        <i class="fas fa-rss"></i> 聚合订阅链接
                    </h3>
                    
                    <div class="alert" style="background: rgba(255, 215, 0, 0.1); border: 1px solid var(--ukraine-yellow); color: var(--ukraine-blue);">
                        <h6><i class="fas fa-info-circle"></i> 注意事项：</h6>
                        <p class="mb-0">以下订阅链接仅6个TLS端口节点</p>
                    </div>
                    
                    <div class="table-ukraine table-responsive">
                        <table class="table table-borderless">
                            <tbody>
                                <tr>
                                    <td style="background: rgba(0, 91, 187, 0.05); font-weight: bold;">
                                        <i class="fas fa-share-alt"></i> 聚合通用分享链接 (可直接导入客户端)
                                    </td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${pgvlessshare}')">
                                            <i class="fas fa-download"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background: rgba(255, 215, 0, 0.05); font-weight: bold;">
                                        <i class="fas fa-link"></i> 聚合通用订阅链接
                                    </td>
                                    <td class="limited-width">${pty}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${pty}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background: rgba(0, 91, 187, 0.05); font-weight: bold;">
                                        <i class="fab fa-cloudflare"></i> Clash-meta订阅链接
                                    </td>
                                    <td class="limited-width">${pcl}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${pcl}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background: rgba(255, 215, 0, 0.05); font-weight: bold;">
                                        <i class="fas fa-box"></i> Sing-box订阅链接
                                    </td>
                                    <td class="limited-width">${psb}</td>
                                    <td>
                                        <button class="btn btn-ukraine" onclick="copyToClipboard('${psb}')">
                                            <i class="fas fa-copy"></i> 复制链接
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
`;
	}
}

function gettyConfig(userID, hostName) {
	const vlessshare = btoa(`vless://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
	return `${vlessshare}`
}

function getsbConfig(userID, hostName) {
	const config = {
		"log": { "level": "debug", "timestamp": true },
		"experimental": { "clash_api": { "external_controller": "127.0.0.1:9090", "secret": "Akama1" } },
		"dns": { "servers": [{ "tag": "google", "address": "tls://8.8.8.8", "strategy": "ipv4_only", "detour": "Proxy" }] },
		"inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }],
		"outbounds": [
			{ "tag": "auto", "type": "urltest", "outbounds": [`CF_V8_${IP8}_${PT8}`, `CF_V9_${IP9}_${PT9}`, `CF_V10_${IP10}_${PT10}`, `CF_V11_${IP11}_${PT11}`, `CF_V12_${IP12}_${PT12}`, `CF_V13_${IP13}_${PT13}`], "url": "http://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50 },
			{
				"tag": `CF_V8_${IP8}_${PT8}`,
				"type": "vless",
				"server": IP8.replace(/[\\[\\]]/g, ''),
				"server_port": parseInt(PT8),
				"uuid": userID,
				"tls": { "enabled": true, "server_name": hostName, "utls": { "enabled": true, "fingerprint": "chrome" } },
				"transport": { "type": "ws", "path": "/?ed=2560", "headers": { "Host": hostName } }
			},
			{ "tag": "direct", "type": "direct" },
			{ "tag": "block", "type": "block" }
		]
	};
	return JSON.stringify(config, null, 2);
}

function getpsbConfig(userID, hostName) {
	return getsbConfig(userID, hostName);
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
- name: LoadBalance
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

- name: Automatic
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
    
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Automatic
`
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
  server: ${IP13。replace(/[\[\]]/g, '')}
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
- name: LoadBalance
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

- name: Automatic
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
    
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Automatic
`
}

function getptyConfig(userID, hostName) {
	const vlessshare = btoa(`vless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
	return `${vlessshare}`
}
