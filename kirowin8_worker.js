//nat64自动填充proxyip，无需且不支持proxyip设置
import { connect } from "cloudflare:sockets";
const WS_READY_STATE_OPEN = 1;
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";
const cn_hostnames = [""];
let CDNIP =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067";
// http_ip
let IP1 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d";
let IP2 =
  "\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d";
let IP3 =
  "\u0061\u0066\u0072\u0069\u0063\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d";
let IP4 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067";
let IP5 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074";
let IP6 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074";
let IP7 =
  "\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d";

// https_ip
let IP8 =
  "\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d";
let IP9 =
  "\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d";
let IP10 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077";
let IP11 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068";
let IP12 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072";
let IP13 =
  "\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d";

// http_port
let PT1 = "80";
let PT2 = "8080";
let PT3 = "8880";
let PT4 = "2052";
let PT5 = "2082";
let PT6 = "2086";
let PT7 = "2095";

// https_port
let PT8 = "443";
let PT9 = "8443";
let PT10 = "2053";
let PT11 = "2083";
let PT12 = "2087";
let PT13 = "2096";

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
            const vlessConfig = getvlessConfig(
              userID,
              request.headers.get("Host")
            );
            return new Response(`${vlessConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
          case `/${userID}/ty`: {
            const tyConfig = gettyConfig(userID, request.headers.get("Host"));
            return new Response(`${tyConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              },
            });
          }
          case `/${userID}/cl`: {
            const clConfig = getclConfig(userID, request.headers.get("Host"));
            return new Response(`${clConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              },
            });
          }
          case `/${userID}/sb`: {
            const sbConfig = getsbConfig(userID, request.headers.get("Host"));
            return new Response(`${sbConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
          }
          case `/${userID}/pty`: {
            const ptyConfig = getptyConfig(userID, request.headers.get("Host"));
            return new Response(`${ptyConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              },
            });
          }
          case `/${userID}/pcl`: {
            const pclConfig = getpclConfig(userID, request.headers.get("Host"));
            return new Response(`${pclConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              },
            });
          }
          case `/${userID}/psb`: {
            const psbConfig = getpsbConfig(userID, request.headers.get("Host"));
            return new Response(`${psbConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
          }
          default:
            // return new Response('Not found', { status: 404 });
            // For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
            if (cn_hostnames.includes("")) {
              return new Response(JSON.stringify(request.cf, null, 4), {
                status: 200,
                headers: {
                  "Content-Type": "application/json;charset=utf-8",
                },
              });
            }
            const randomHostname =
              cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set(
              "referer",
              "https://www.google.com/search?q=edtunnel"
            );
            // Use fetch to proxy the request to 15 different domains
            const proxyUrl =
              "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, {
              redirect: "manual",
            });
            // Check for 302 or 301 redirect status and return an error response
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(
                `Redirects to ${randomHostname} are not allowed.`,
                {
                  status: 403,
                  statusText: "Forbidden",
                }
              );
            }
            // Return the response from the proxy server
            return proxyResponse;
        }
      }
      return await handlevlessWebSocket(request);
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

async function handlevlessWebSocket(request) {
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
  let remoteSocket = null;

  let udpStreamWrite = null;
  let isDns = false;

  wsReadable
    .pipeTo(
      new WritableStream({
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

          const result = parsevlessHeader(chunk, userID);
          if (result.hasError) {
            throw new Error(result.message);
          }

          const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
          const rawClientData = chunk.slice(result.rawDataIndex);

          if (result.isUDP) {
            if (result.portRemote === 53) {
              isDns = true;
              const { write } = await handleUDPOutBound(
                serverWS,
                vlessRespHeader
              );
              udpStreamWrite = write;
              udpStreamWrite(rawClientData);
              return;
            } else {
              throw new Error("UDP代理仅支持DNS(端口53)");
            }
          }

          async function connectAndWrite(address, port) {
            const tcpSocket = await connect({
              hostname: address,
              port: port,
            });
            remoteSocket = tcpSocket;
            const writer = tcpSocket.writable.getWriter();
            await writer.write(rawClientData);
            writer.releaseLock();
            return tcpSocket;
          }

          function convertToNAT64IPv6(ipv4Address) {
            const parts = ipv4Address.split(".");
            if (parts.length !== 4) {
              throw new Error("无效的IPv4地址");
            }

            const hex = parts.map((part) => {
              const num = parseInt(part, 10);
              if (num < 0 || num > 255) {
                throw new Error("无效的IPv4地址段");
              }
              return num.toString(16).padStart(2, "0");
            });
            const prefixes = ["2602:fc59:b0:64::"]; //2001:67c:2960:6464::
            const chosenPrefix =
              prefixes[Math.floor(Math.random() * prefixes.length)];
            return `[${chosenPrefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
          }

          async function getIPv6ProxyAddress(domain) {
            try {
              const dnsQuery = await fetch(
                `https://1.1.1.1/dns-query?name=${domain}&type=A`,
                {
                  headers: {
                    Accept: "application/dns-json",
                  },
                }
              );

              const dnsResult = await dnsQuery.json();
              if (dnsResult.Answer && dnsResult.Answer.length > 0) {
                const aRecord = dnsResult.Answer.find(
                  (record) => record.type === 1
                );
                if (aRecord) {
                  const ipv4Address = aRecord.data;
                  return convertToNAT64IPv6(ipv4Address);
                }
              }
              throw new Error("无法解析域名的IPv4地址");
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
                port: result.portRemote,
              });
              remoteSocket = tcpSocket;
              const writer = tcpSocket.writable.getWriter();
              await writer.write(rawClientData);
              writer.releaseLock();

              tcpSocket.closed
                .catch((error) => {
                  console.error("NAT64 IPv6连接关闭错误:", error);
                })
                .finally(() => {
                  if (serverWS.readyState === WS_READY_STATE_OPEN) {
                    serverWS.close(1000, "连接已关闭");
                  }
                });

              pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, null);
            } catch (err) {
              console.error("NAT64 IPv6连接失败:", err);
              serverWS.close(1011, "NAT64 IPv6连接失败: " + err.message);
            }
          }

          try {
            const tcpSocket = await connectAndWrite(
              result.addressRemote,
              result.portRemote
            );
            pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, retry);
          } catch (err) {
            console.error("连接失败:", err);
            serverWS.close(1011, "连接失败");
          }
        },
        close() {
          if (remoteSocket) {
            closeSocket(remoteSocket);
          }
        },
      })
    )
    .catch((err) => {
      console.error("WebSocket 错误:", err);
      closeSocket(remoteSocket);
      serverWS.close(1011, "内部错误");
    });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

function createWebSocketReadableStream(ws, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });

      ws.addEventListener("close", () => {
        controller.close();
      });

      ws.addEventListener("error", (err) => {
        controller.error(err);
      });

      if (earlyDataHeader) {
        try {
          const decoded = atob(
            earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/")
          );
          const data = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
          controller.enqueue(data.buffer);
        } catch (e) {}
      }
    },
  });
}

function parsevlessHeader(buffer, userID) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: "无效的头部长度" };
  }

  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));

  const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
  if (uuid !== userID) {
    return { hasError: true, message: "无效的用户" };
  }

  const optionsLength = view.getUint8(17);
  const command = view.getUint8(18 + optionsLength);

  let isUDP = false;
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: "不支持的命令，仅支持TCP(01)和UDP(02)" };
  }

  let offset = 19 + optionsLength;
  const port = view.getUint16(offset);
  offset += 2;

  const addressType = view.getUint8(offset++);
  let address = "";

  switch (addressType) {
    case 1: // IPv4
      address = Array.from(
        new Uint8Array(buffer.slice(offset, offset + 4))
      ).join(".");
      offset += 4;
      break;

    case 2: // 域名
      const domainLength = view.getUint8(offset++);
      address = new TextDecoder().decode(
        buffer.slice(offset, offset + domainLength)
      );
      offset += domainLength;
      break;

    case 3: // IPv6
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(view.getUint16(offset).toString(16).padStart(4, "0"));
        offset += 2;
      }
      address = ipv6.join(":").replace(/(^|:)0+(\w)/g, "$1$2");
      break;

    default:
      return { hasError: true, message: "不支持的地址类型" };
  }

  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: offset,
    vlessVersion: version,
    isUDP,
  };
}

function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader, retry = null) {
  let headerSent = false;
  let hasIncomingData = false;

  remoteSocket.readable
    .pipeTo(
      new WritableStream({
        write(chunk) {
          hasIncomingData = true;
          if (ws.readyState === WS_READY_STATE_OPEN) {
            if (!headerSent) {
              const combined = new Uint8Array(
                vlessHeader.byteLength + chunk.byteLength
              );
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
            ws.close(1000, "正常关闭");
          }
        },
        abort() {
          closeSocket(remoteSocket);
        },
      })
    )
    .catch((err) => {
      console.error("数据转发错误:", err);
      closeSocket(remoteSocket);
      if (ws.readyState === WS_READY_STATE_OPEN) {
        ws.close(1011, "数据传输错误");
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
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(
    ""
  );
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(
    12,
    16
  )}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function handleUDPOutBound(webSocket, vlessResponseHeader) {
  let isvlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPacketLength)
        );
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch("https://1.1.1.1/dns-query", {
            method: "POST",
            headers: {
              "content-type": "application/dns-message",
            },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([
            (udpSize >> 8) & 0xff,
            udpSize & 0xff,
          ]);

          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            console.log(`DNS查询成功，DNS消息长度为 ${udpSize}`);
            if (isvlessHeaderSent) {
              webSocket.send(
                await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer()
              );
            } else {
              webSocket.send(
                await new Blob([
                  vlessResponseHeader,
                  udpSizeBuffer,
                  dnsQueryResult,
                ]).arrayBuffer()
              );
              isvlessHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      console.error("DNS UDP处理错误:", error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}
/**
 *
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function getvlessConfig(userID, hostName) {
  const wvlessws = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
  const pvlesswstls = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
  const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP使用nat64自动生成，无需设置`;
  const ty = `https://${hostName}/${userID}/ty`;
  const cl = `https://${hostName}/${userID}/cl`;
  const sb = `https://${hostName}/${userID}/sb`;
  const pty = `https://${hostName}/${userID}/pty`;
  const pcl = `https://${hostName}/${userID}/pcl`;
  const psb = `https://${hostName}/${userID}/psb`;

  const wkvlessshare = btoa(
    `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`
  );

  const pgvlessshare = btoa(
    `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`
  );

  const noteshow = note.replace(/\n/g, "<br>");
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #1e1e1e;
    color: #ffffff;
    overflow-x: hidden;
}

.metro-container {
    padding: 40px;
    max-width: 1400px;
    margin: 0 auto;
}

.metro-header {
    margin-bottom: 40px;
}

.metro-title {
    font-size: 42px;
    font-weight: 300;
    color: #ffffff;
    margin-bottom: 10px;
}

.metro-subtitle {
    font-size: 18px;
    color: #cccccc;
    font-weight: 300;
}

.metro-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 20px;
    margin-bottom: 40px;
}

.metro-tile {
    position: relative;
    padding: 30px;
    border: none;
    cursor: pointer;
    transition: all 0.2s ease;
    overflow: hidden;
    min-height: 160px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.metro-tile:hover {
    transform: scale(1.02);
    filter: brightness(1.1);
}

.metro-tile:active {
    transform: scale(0.98);
}

.tile-primary { background: #0078d4; }
.tile-success { background: #107c10; }
.tile-warning { background: #ff8c00; }
.tile-danger { background: #d13438; }
.tile-info { background: #00bcf2; }
.tile-purple { background: #881798; }
.tile-teal { background: #00b7c3; }

.tile-icon {
    font-size: 32px;
    margin-bottom: 15px;
    opacity: 0.9;
}

.tile-title {
    font-size: 20px;
    font-weight: 400;
    margin-bottom: 8px;
    line-height: 1.2;
}

.tile-content {
    font-size: 14px;
    opacity: 0.9;
    line-height: 1.4;
    word-break: break-all;
}

.tile-wide {
    grid-column: span 2;
    min-height: 200px;
}

.tile-tall {
    grid-row: span 2;
    min-height: 340px;
}

.config-section {
    background: #2d2d30;
    padding: 30px;
    margin-bottom: 20px;
    border-left: 4px solid #0078d4;
}

.config-title {
    font-size: 24px;
    font-weight: 300;
    margin-bottom: 20px;
    color: #ffffff;
}

.config-list {
    list-style: none;
    padding: 0;
}

.config-list li {
    padding: 8px 0;
    border-bottom: 1px solid #404040;
    font-size: 14px;
    color: #cccccc;
}

.config-list li:last-child {
    border-bottom: none;
}

.config-list strong {
    color: #ffffff;
    font-weight: 400;
}

.notification-badge {
    position: absolute;
    top: 15px;
    right: 15px;
    background: rgba(255, 255, 255, 0.2);
    color: white;
    border-radius: 50%;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: bold;
}

.live-tile {
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.8; }
}

.copy-success {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: #107c10;
    color: white;
    padding: 20px 40px;
    border-radius: 0;
    font-size: 16px;
    z-index: 1000;
    animation: fadeInOut 2s ease-in-out;
}

@keyframes fadeInOut {
    0%, 100% { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
    20%, 80% { opacity: 1; transform: translate(-50%, -50%) scale(1); }
}

@media (max-width: 768px) {
    .metro-container { padding: 20px; }
    .metro-title { font-size: 32px; }
    .metro-grid { grid-template-columns: 1fr; }
    .tile-wide { grid-column: span 1; }
    .tile-tall { grid-row: span 1; min-height: 160px; }
}
</style>
</head>
<script>
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showCopySuccess();
    }).catch(function() {
        // Fallback for older browsers
        const input = document.createElement('textarea');
        input.style.position = 'fixed';
        input.style.opacity = 0;
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('Copy');
        document.body.removeChild(input);
        showCopySuccess();
    });
}

function showCopySuccess() {
    const notification = document.createElement('div');
    notification.className = 'copy-success';
    notification.textContent = '✓ 已复制到剪贴板';
    document.body.appendChild(notification);
    setTimeout(() => {
        document.body.removeChild(notification);
    }, 2000);
}
</script>
`;
  if (hostName.includes("workers.dev")) {
    return `
${displayHtml}
<body>
<div class="metro-container">
    <div class="metro-header">
        <h1 class="metro-title">VLESS 代理服务</h1>
        <p class="metro-subtitle">Cloudflare Workers • 版本 25.5.27</p>
    </div>

    <div class="metro-grid">
        <!-- 主要节点磁贴 -->
        <div class="metro-tile tile-primary tile-wide" onclick="copyToClipboard('${wvlessws}')">
            <div class="tile-icon">🔗</div>
            <div class="tile-title">VLESS + WebSocket</div>
            <div class="tile-content">无TLS加密 • 无视域名阻断</div>
            <div class="notification-badge">WS</div>
        </div>

        <div class="metro-tile tile-success" onclick="copyToClipboard('${pvlesswstls}')">
            <div class="tile-icon">🔒</div>
            <div class="tile-title">VLESS + TLS</div>
            <div class="tile-content">安全加密连接</div>
            <div class="notification-badge">TLS</div>
        </div>

        <!-- 订阅链接磁贴 -->
        <div class="metro-tile tile-warning" onclick="copyToClipboard('${ty}')">
            <div class="tile-icon">📋</div>
            <div class="tile-title">通用订阅</div>
            <div class="tile-content">支持多种客户端</div>
        </div>

        <div class="metro-tile tile-info" onclick="copyToClipboard('${cl}')">
            <div class="tile-icon">⚡</div>
            <div class="tile-title">Clash Meta</div>
            <div class="tile-content">专用订阅格式</div>
        </div>

        <div class="metro-tile tile-purple" onclick="copyToClipboard('${sb}')">
            <div class="tile-icon">📦</div>
            <div class="tile-title">Sing-box</div>
            <div class="tile-content">现代代理工具</div>
        </div>

        <!-- 批量分享磁贴 -->
        <div class="metro-tile tile-danger tile-wide" onclick="copyToClipboard('${wkvlessshare}')">
            <div class="tile-icon">🚀</div>
            <div class="tile-title">批量节点分享</div>
            <div class="tile-content">包含13个端口的完整节点列表</div>
            <div class="notification-badge">13</div>
        </div>

        <!-- 信息磁贴 -->
        <div class="metro-tile tile-teal tile-tall live-tile">
            <div class="tile-icon">ℹ️</div>
            <div class="tile-title">使用说明</div>
            <div class="tile-content">
                • 支持TCP和UDP代理<br>
                • 自动NAT64 IPv6回退<br>
                • 多端口负载均衡<br>
                • 实时连接状态监控
            </div>
        </div>
    </div>

    <!-- 配置详情 -->
    <div class="config-section">
        <h2 class="config-title">WebSocket 节点配置</h2>
        <ul class="config-list">
            <li><strong>服务器地址：</strong>自定义域名 或 优选IP</li>
            <li><strong>端口：</strong>80, 8080, 8880, 2052, 2082, 2086, 2095</li>
            <li><strong>用户ID：</strong>${userID}</li>
            <li><strong>传输协议：</strong>WebSocket</li>
            <li><strong>伪装域名：</strong>${hostName}</li>
            <li><strong>路径：</strong>/?ed=2560</li>
            <li><strong>传输安全：</strong>关闭</li>
        </ul>
    </div>

    <div class="config-section">
        <h2 class="config-title">TLS 加密节点配置</h2>
        <ul class="config-list">
            <li><strong>服务器地址：</strong>自定义域名 或 优选IP</li>
            <li><strong>端口：</strong>443, 8443, 2053, 2083, 2087, 2096</li>
            <li><strong>用户ID：</strong>${userID}</li>
            <li><strong>传输协议：</strong>WebSocket</li>
            <li><strong>伪装域名：</strong>${hostName}</li>
            <li><strong>路径：</strong>/?ed=2560</li>
            <li><strong>传输安全：</strong>开启</li>
            <li><strong>证书验证：</strong>启用</li>
        </ul>
    </div>

    <div class="config-section">
        <h2 class="config-title">重要提示</h2>
        <ul class="config-list">
            <li>每个订阅包含TLS+非TLS共13个端口节点</li>
            <li>Workers域名订阅需通过代理更新</li>
            <li>TLS节点建议开启分片功能防止域名阻断</li>
            <li>支持UDP DNS查询（端口53）</li>
            <li>连接失败时自动尝试NAT64 IPv6</li>
        </ul>
    </div>
</div>
</body>
`;
  } else {
    return `
${displayHtml}
<body>
<div class="metro-container">
    <div class="metro-header">
        <h1 class="metro-title">VLESS 代理服务</h1>
        <p class="metro-subtitle">Cloudflare Pages • 自定义域名 • 版本 25.5.27</p>
    </div>

    <div class="metro-grid">
        <!-- 主要TLS节点磁贴 -->
        <div class="metro-tile tile-success tile-wide" onclick="copyToClipboard('${pvlesswstls}')">
            <div class="tile-icon">🔐</div>
            <div class="tile-title">VLESS + TLS 安全连接</div>
            <div class="tile-content">自定义域名 • 完整TLS加密 • 防域名阻断</div>
            <div class="notification-badge">TLS</div>
        </div>

        <!-- 订阅链接磁贴 -->
        <div class="metro-tile tile-warning" onclick="copyToClipboard('${pty}')">
            <div class="tile-icon">📋</div>
            <div class="tile-title">通用订阅</div>
            <div class="tile-content">支持多种客户端</div>
        </div>

        <div class="metro-tile tile-info" onclick="copyToClipboard('${pcl}')">
            <div class="tile-icon">⚡</div>
            <div class="tile-title">Clash Meta</div>
            <div class="tile-content">专用订阅格式</div>
        </div>

        <div class="metro-tile tile-purple" onclick="copyToClipboard('${psb}')">
            <div class="tile-icon">📦</div>
            <div class="tile-title">Sing-box</div>
            <div class="tile-content">现代代理工具</div>
        </div>

        <!-- 批量分享磁贴 -->
        <div class="metro-tile tile-primary tile-wide" onclick="copyToClipboard('${pgvlessshare}')">
            <div class="tile-icon">🚀</div>
            <div class="tile-title">TLS 节点分享</div>
            <div class="tile-content">包含6个HTTPS端口的安全节点列表</div>
            <div class="notification-badge">6</div>
        </div>

        <!-- 信息磁贴 -->
        <div class="metro-tile tile-teal tile-tall live-tile">
            <div class="tile-icon">🛡️</div>
            <div class="tile-title">安全特性</div>
            <div class="tile-content">
                • 完整TLS加密保护<br>
                • 自定义域名支持<br>
                • 分片功能防阻断<br>
                • 6个HTTPS端口可选
            </div>
        </div>

        <!-- 域名信息磁贴 -->
        <div class="metro-tile tile-danger live-tile">
            <div class="tile-icon">🌐</div>
            <div class="tile-title">当前域名</div>
            <div class="tile-content">${hostName}</div>
        </div>
    </div>

    <!-- 配置详情 -->
    <div class="config-section">
        <h2 class="config-title">TLS 加密节点配置</h2>
        <ul class="config-list">
            <li><strong>服务器地址：</strong>自定义域名 或 优选IP</li>
            <li><strong>端口：</strong>443, 8443, 2053, 2083, 2087, 2096</li>
            <li><strong>用户ID：</strong>${userID}</li>
            <li><strong>传输协议：</strong>WebSocket</li>
            <li><strong>伪装域名：</strong>${hostName}</li>
            <li><strong>路径：</strong>/?ed=2560</li>
            <li><strong>传输安全：</strong>开启</li>
            <li><strong>证书验证：</strong>启用</li>
        </ul>
    </div>

    <div class="config-section">
        <h2 class="config-title">重要提示</h2>
        <ul class="config-list">
            <li>此配置仅包含6个TLS端口节点</li>
            <li>建议开启客户端分片功能防止域名阻断</li>
            <li>自定义域名提供更好的稳定性</li>
            <li>支持UDP DNS查询（端口53）</li>
            <li>连接失败时自动尝试NAT64 IPv6</li>
        </ul>
    </div>
</div>
</body>
`;
  }
}

function gettyConfig(userID, hostName) {
  const vlessshare = btoa(
    `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`
  );
  return `${vlessshare}`;
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
  server: ${IP1.replace(/[\[\]]/g, "")}
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
  server: ${IP2.replace(/[\[\]]/g, "")}
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
  server: ${IP3.replace(/[\[\]]/g, "")}
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
  server: ${IP4.replace(/[\[\]]/g, "")}
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
  server: ${IP5.replace(/[\[\]]/g, "")}
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
  server: ${IP6.replace(/[\[\]]/g, "")}
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
  server: ${IP7.replace(/[\[\]]/g, "")}
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
  server: ${IP8.replace(/[\[\]]/g, "")}
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
  server: ${IP9.replace(/[\[\]]/g, "")}
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
  server: ${IP10.replace(/[\[\]]/g, "")}
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
  server: ${IP11.replace(/[\[\]]/g, "")}
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
  server: ${IP12.replace(/[\[\]]/g, "")}
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
  server: ${IP13.replace(/[\[\]]/g, "")}
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
  - MATCH,🌍选择代理`;
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
	}`;
}

function getptyConfig(userID, hostName) {
  const vlessshare = btoa(
    `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`
  );
  return `${vlessshare}`;
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
  server: ${IP8.replace(/[\[\]]/g, "")}
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
  server: ${IP9.replace(/[\[\]]/g, "")}
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
  server: ${IP10.replace(/[\[\]]/g, "")}
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
  server: ${IP11.replace(/[\[\]]/g, "")}
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
  server: ${IP12.replace(/[\[\]]/g, "")}
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
  server: ${IP13.replace(/[\[\]]/g, "")}
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
  - MATCH,🌍选择代理`;
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
