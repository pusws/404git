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
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
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
function get\u0076\u006c\u0065\u0073\u0073Config(userID, hostName) {
  const w\u0076\u006c\u0065\u0073\u0073ws = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
  const p\u0076\u006c\u0065\u0073\u0073wstls = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
  const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP使用nat64自动生成，无需设置`;
  const ty = `https://${hostName}/${userID}/ty`
  const cl = `https://${hostName}/${userID}/cl`
  const sb = `https://${hostName}/${userID}/sb`
  const pty = `https://${hostName}/${userID}/pty`
  const pcl = `https://${hostName}/${userID}/pcl`
  const psb = `https://${hostName}/${userID}/psb`

  const wk\u0076\u006c\u0065\u0073\u0073share = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);


  const pg\u0076\u006c\u0065\u0073\u0073share = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);	

	
  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
/* 乌克兰主题样式 */
:root {
    --ukraine-blue: #005BBB;
    --ukraine-yellow: #FFD700;
    --ukraine-blue-light: #1a6bc4;
    --ukraine-yellow-light: #ffdd33;
    --text-dark: #2c3e50;
    --text-light: #ecf0f1;
    --shadow: rgba(0, 91, 187, 0.1);
}

body {
    background: linear-gradient(135deg, var(--ukraine-blue) 0%, var(--ukraine-yellow) 100%);
    min-height: 100vh;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.ukraine-container {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    box-shadow: 0 20px 40px var(--shadow);
    backdrop-filter: blur(10px);
    border: 2px solid var(--ukraine-blue);
    overflow: hidden;
}

.ukraine-header {
    background: linear-gradient(90deg, var(--ukraine-blue) 50%, var(--ukraine-yellow) 50%);
    color: white;
    padding: 2rem;
    text-align: center;
    position: relative;
}

.ukraine-header::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20"><rect width="50" height="20" fill="%23005BBB"/><rect x="50" width="50" height="20" fill="%23FFD700"/></svg>') repeat-x;
    opacity: 0.1;
}

.ukraine-header h1 {
    margin: 0;
    font-weight: 700;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    position: relative;
    z-index: 1;
}

.ukraine-content {
    padding: 2rem;
}

.ukraine-card {
    background: white;
    border-radius: 15px;
    border: 2px solid var(--ukraine-blue);
    margin-bottom: 2rem;
    overflow: hidden;
    transition: all 0.3s ease;
}

.ukraine-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 30px var(--shadow);
}

.ukraine-card-header {
    background: var(--ukraine-blue);
    color: white;
    padding: 1rem 1.5rem;
    margin: 0;
    font-weight: 600;
    border-bottom: 3px solid var(--ukraine-yellow);
}

.ukraine-table {
    width: 100%;
    border-collapse: collapse;
}

.ukraine-table th {
    background: var(--ukraine-blue);
    color: white;
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    border: none;
}

.ukraine-table td {
    padding: 1rem;
    border-bottom: 1px solid rgba(0, 91, 187, 0.1);
    vertical-align: middle;
}

.ukraine-table tr:nth-child(even) {
    background: rgba(255, 215, 0, 0.05);
}

.ukraine-table tr:hover {
    background: rgba(0, 91, 187, 0.05);
}

.ukraine-btn {
    background: linear-gradient(45deg, var(--ukraine-blue), var(--ukraine-blue-light));
    border: none;
    color: white;
    padding: 0.75rem 1.5rem;
    border-radius: 25px;
    font-weight: 600;
    text-decoration: none;
    display: inline-block;
    transition: all 0.3s ease;
    cursor: pointer;
    box-shadow: 0 4px 15px rgba(0, 91, 187, 0.3);
}

.ukraine-btn:hover {
    background: linear-gradient(45deg, var(--ukraine-blue-light), var(--ukraine-blue));
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(0, 91, 187, 0.4);
    color: white;
}

.ukraine-btn:active {
    transform: translateY(0);
}

.ukraine-alert {
    background: var(--ukraine-yellow);
    color: var(--text-dark);
    border: 2px solid var(--ukraine-blue);
    border-radius: 10px;
    padding: 1rem;
    margin: 1rem 0;
    font-weight: 500;
}

.ukraine-note {
    background: rgba(255, 215, 0, 0.1);
    border-left: 4px solid var(--ukraine-yellow);
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 0 10px 10px 0;
}

.limited-width {
    max-width: 300px;
    overflow: auto;
    word-wrap: break-word;
    font-family: 'Courier New', monospace;
    font-size: 0.9rem;
    background: rgba(0, 91, 187, 0.05);
    padding: 0.5rem;
    border-radius: 5px;
    border: 1px solid rgba(0, 91, 187, 0.2);
}

.ukraine-flag-decoration {
    position: absolute;
    top: 10px;
    right: 10px;
    width: 40px;
    height: 20px;
    background: linear-gradient(to right, var(--ukraine-blue) 50%, var(--ukraine-yellow) 50%);
    border-radius: 3px;
    opacity: 0.8;
}

/* 乌克兰支持声明样式 */
.ukraine-declaration {
    background: linear-gradient(135deg, rgba(0, 91, 187, 0.1), rgba(255, 215, 0, 0.1));
    border: 3px solid var(--ukraine-blue);
    border-radius: 20px;
    padding: 2rem;
    margin: 2rem 0;
    position: relative;
    overflow: hidden;
    box-shadow: 0 10px 30px rgba(0, 91, 187, 0.2);
}

.ukraine-declaration::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20"><rect width="50" height="20" fill="%23005BBB"/><rect x="50" width="50" height="20" fill="%23FFD700"/></svg>') repeat-x;
    opacity: 0.05;
    pointer-events: none;
}

.ukraine-declaration .declaration-content {
    position: relative;
    z-index: 1;
    display: flex;
    align-items: flex-start;
    gap: 1.5rem;
}

.ukraine-declaration .declaration-flag {
    font-size: 3rem;
    flex-shrink: 0;
    filter: drop-shadow(2px 2px 4px rgba(0,0,0,0.3));
}

.ukraine-declaration .declaration-text {
    flex: 1;
}

.ukraine-declaration h4 {
    color: var(--ukraine-blue);
    margin: 0 0 1rem 0;
    font-size: 1.5rem;
    font-weight: 700;
    text-shadow: 1px 1px 2px rgba(0,0,0,0.1);
}

.ukraine-declaration p {
    margin: 0.5rem 0;
    line-height: 1.6;
    color: var(--text-dark);
    font-weight: 500;
}

.ukraine-declaration em {
    font-style: italic;
    color: var(--ukraine-blue);
    font-weight: 600;
}

.ukraine-declaration hr {
    border: none;
    height: 2px;
    background: linear-gradient(to right, var(--ukraine-blue), var(--ukraine-yellow));
    margin: 1.5rem 0;
}

@media (max-width: 768px) {
    .ukraine-declaration {
        padding: 1.5rem;
        margin: 1.5rem 0;
    }

    .ukraine-declaration .declaration-content {
        flex-direction: column;
        text-align: center;
        gap: 1rem;
    }

    .ukraine-declaration .declaration-flag {
        font-size: 2.5rem;
        align-self: center;
    }

    .ukraine-declaration h4 {
        font-size: 1.3rem;
    }
}

@media (max-width: 768px) {
    .ukraine-container {
        margin: 1rem;
        border-radius: 15px;
    }

    .ukraine-header {
        padding: 1.5rem;
    }

    .ukraine-content {
        padding: 1rem;
    }

    .ukraine-table {
        font-size: 0.9rem;
    }

    .ukraine-table th,
    .ukraine-table td {
        padding: 0.5rem;
    }

    .limited-width {
        max-width: 200px;
        font-size: 0.8rem;
    }
}

/* 复制成功提示动画 */
.copy-success {
    position: fixed;
    top: 20px;
    right: 20px;
    background: var(--ukraine-yellow);
    color: var(--text-dark);
    padding: 1rem 2rem;
    border-radius: 25px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    z-index: 1000;
    animation: slideIn 0.3s ease-out;
    border: 2px solid var(--ukraine-blue);
}

@keyframes slideIn {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

.fade-out {
    animation: fadeOut 0.3s ease-out 2s forwards;
}

@keyframes fadeOut {
    to {
        transform: translateX(100%);
        opacity: 0;
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
  showCopySuccess();
}

function showCopySuccess() {
  const notification = document.createElement('div');
  notification.className = 'copy-success';
  notification.innerHTML = '<strong>✓ 已复制到剪贴板</strong>';
  document.body.appendChild(notification);

  setTimeout(() => {
    notification.classList.add('fade-out');
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }, 2000);
}
</script>
`;
if (hostName.includes("workers.dev")) {
return `
<br>
<br>
${displayHtml}
<body>
<div class="ukraine-container">
    <div class="ukraine-header">
        <div class="ukraine-flag-decoration"></div>
        <h1>Cloudflare-workers/pages-\u0076\u006c\u0065\u0073\u0073代理脚本 V25.5.27</h1>
    </div>
    <div class="ukraine-content">
        <!-- 乌克兰支持声明 -->
        <div class="ukraine-declaration">
            <div class="declaration-content">
                <div class="declaration-flag">
                    🇺🇦
                </div>
                <div class="declaration-text">
                    <h4>🇺🇦 支持乌克兰 - 谴责俄罗斯侵略 🇺🇦</h4>
                    <p><strong>我们坚定支持乌克兰人民抵抗俄罗斯侵略的正义斗争！</strong></p>
                    <p>俄罗斯对乌克兰的侵略战争犯下了严重的战争罪行，包括对平民的轰炸、强奸、酷刑和大规模破坏。我们谴责这种野蛮行径，并呼吁立即停止侵略，恢复乌克兰的领土完整和主权。</p>
                    <p><em>Slava Ukraini! Героям слава! Glory to Ukraine! Glory to the heroes!</em></p>
                    <hr>
                    <p><strong>We firmly support the Ukrainian people's just struggle against Russian aggression!</strong></p>
                    <p>Russia's invasion of Ukraine has committed serious war crimes, including bombing civilians, rape, torture and massive destruction. We condemn these barbaric acts and call for an immediate end to the aggression and the restoration of Ukraine's territorial integrity and sovereignty.</p>
                    <p><em>Slava Ukraini! Героям слава! Glory to Ukraine! Glory to the heroes!</em></p>
                </div>
            </div>
        </div>

        <div class="ukraine-note">
            ${noteshow}
        </div>

        <div class="ukraine-card">
            <h3 class="ukraine-card-header">1：CF-workers-\u0076\u006c\u0065\u0073\u0073+ws节点</h3>
            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>节点特色：</th>
                        <th>单节点链接如下：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">关闭了TLS加密，无视域名阻断</td>
                        <td class="limited-width">${w\u0076\u006c\u0065\u0073\u0073ws}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${w\u0076\u006c\u0065\u0073\u0073ws}')">点击复制链接</button></td>
                    </tr>
                </tbody>
            </table>
            <div class="ukraine-alert">
                <strong>客户端参数如下：</strong>
                <ul>
                    <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                    <li>端口(port)：7个http端口可任意选择(80、8080、8880、2052、2082、2086、2095)，或反代IP对应端口</li>
                    <li>用户ID(uuid)：${userID}</li>
                    <li>传输协议(network)：ws 或者 websocket</li>
                    <li>伪装域名(host)：${hostName}</li>
                    <li>路径(path)：/?ed=2560</li>
                    <li>传输安全(TLS)：关闭</li>
                </ul>
            </div>
        </div>

        <div class="ukraine-card">
            <h3 class="ukraine-card-header">2：CF-workers-\u0076\u006c\u0065\u0073\u0073+ws+tls节点</h3>
            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>节点特色：</th>
                        <th>单节点链接如下：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，建议开启，防止域名阻断</td>
                        <td class="limited-width">${p\u0076\u006c\u0065\u0073\u0073wstls}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${p\u0076\u006c\u0065\u0073\u0073wstls}')">点击复制链接</button></td>
                    </tr>
                </tbody>
            </table>
            <div class="ukraine-alert">
                <strong>客户端参数如下：</strong>
                <ul>
                    <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                    <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                    <li>用户ID(uuid)：${userID}</li>
                    <li>传输协议(network)：ws 或者 websocket</li>
                    <li>伪装域名(host)：${hostName}</li>
                    <li>路径(path)：/?ed=2560</li>
                    <li>传输安全(TLS)：开启</li>
                    <li>跳过证书验证(allowlnsecure)：false</li>
                </ul>
            </div>
        </div>

        <div class="ukraine-card">
            <h3 class="ukraine-card-header">3：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
            <div class="ukraine-note">
                <strong>注意：</strong><br>
                1、默认每个订阅链接包含TLS+非TLS共13个端口节点<br>
                2、当前workers域名作为订阅链接，需通过代理进行订阅更新<br>
                3、如使用的客户端不支持分片功能，则TLS节点不可用
            </div>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>聚合通用分享链接 (可直接导入客户端)：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${wk\u0076\u006c\u0065\u0073\u0073share}')">点击复制链接</button></td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${wk\u0076\u006c\u0065\u0073\u0073share}')">复制</button></td>
                    </tr>
                </tbody>
            </table>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>聚合通用订阅链接：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${ty}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${ty}')">复制</button></td>
                    </tr>
                </tbody>
            </table>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>Clash-meta订阅链接：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${cl}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${cl}')">复制</button></td>
                    </tr>
                </tbody>
            </table>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>Sing-box订阅链接：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${sb}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${sb}')">复制</button></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
`;
  } else {
    return `
<br>
<br>
${displayHtml}
<body>
<div class="ukraine-container">
    <div class="ukraine-header">
        <div class="ukraine-flag-decoration"></div>
        <h1>Cloudflare-workers/pages-\u0076\u006c\u0065\u0073\u0073代理脚本 V25.5.27</h1>
    </div>
    <div class="ukraine-content">
        <div class="ukraine-note">
            ${noteshow}
        </div>

        <div class="ukraine-card">
            <h3 class="ukraine-card-header">1：CF-pages/workers/自定义域-\u0076\u006c\u0065\u0073\u0073+ws+tls节点</h3>
            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>节点特色：</th>
                        <th>单节点链接如下：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，可开启，防止域名阻断</td>
                        <td class="limited-width">${p\u0076\u006c\u0065\u0073\u0073wstls}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${p\u0076\u006c\u0065\u0073\u0073wstls}')">点击复制链接</button></td>
                    </tr>
                </tbody>
            </table>
            <div class="ukraine-alert">
                <strong>客户端参数如下：</strong>
                <ul>
                    <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                    <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                    <li>用户ID(uuid)：${userID}</li>
                    <li>传输协议(network)：ws 或者 websocket</li>
                    <li>伪装域名(host)：${hostName}</li>
                    <li>路径(path)：/?ed=2560</li>
                    <li>传输安全(TLS)：开启</li>
                    <li>跳过证书验证(allowlnsecure)：false</li>
                </ul>
            </div>
        </div>

        <div class="ukraine-card">
            <h3 class="ukraine-card-header">2：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
            <div class="ukraine-note">
                <strong>注意：</strong>以下订阅链接仅6个TLS端口节点
            </div>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>聚合通用分享链接 (可直接导入客户端)：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${pg\u0076\u006c\u0065\u0073\u0073share}')">点击复制链接</button></td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${pg\u0076\u006c\u0065\u0073\u0073share}')">复制</button></td>
                    </tr>
                </tbody>
            </table>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>聚合通用订阅链接：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pty}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${pty}')">复制</button></td>
                    </tr>
                </tbody>
            </table>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>Clash-meta订阅链接：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pcl}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${pcl}')">复制</button></td>
                    </tr>
                </tbody>
            </table>

            <table class="ukraine-table">
                <thead>
                    <tr>
                        <th>Sing-box订阅链接：</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${psb}</td>
                        <td><button class="ukraine-btn" onclick="copyToClipboard('${psb}')">复制</button></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
`;
  }
}

function gettyConfig(userID, hostName) {
	const \u0076\u006c\u0065\u0073\u0073share = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
		return `${\u0076\u006c\u0065\u0073\u0073share}`
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
		  "type": "\u0076\u006c\u0065\u0073\u0073",
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
	const \u0076\u006c\u0065\u0073\u0073share = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);	
		return `${\u0076\u006c\u0065\u0073\u0073share}`
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
  type: \u0076\u006c\u0065\u0073\u0073
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
			  "type": "\u0076\u006c\u0065\u0073\u0073",
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
			  "type": "\u0076\u006c\u0065\u0073\u0073",
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
			  "type": "\u0076\u006c\u0065\u0073\u0073",
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
			  "type": "\u0076\u006c\u0065\u0073\u0073",
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
			  "type": "\u0076\u006c\u0065\u0073\u0073",
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
			  "type": "\u0076\u006c\u0065\u0073\u0073",
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
