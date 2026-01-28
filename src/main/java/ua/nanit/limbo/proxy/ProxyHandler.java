package ua.nanit.limbo.proxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class ProxyHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
    private final ProxyConfig config;
    private Channel outboundChannel;
    private boolean firstMessage = true;

    public ProxyHandler(ProxyConfig config) {
        this.config = config;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame frame) throws Exception {
        if (!(frame instanceof BinaryWebSocketFrame)) {
            return;
        }

        ByteBuf buf = frame.content();
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);

        if (firstMessage) {
            firstMessage = false;

            if (data.length > 17 && data[0] == 0) {
                if (tryVless(ctx, data)) {
                    return;
                }
            }

            if (tryTrojan(ctx, data)) {
                return;
            }

            ctx.close();
            return;
        }

        if (outboundChannel != null && outboundChannel.isActive()) {
            outboundChannel.writeAndFlush(Unpooled.wrappedBuffer(data));
        }
    }

    private boolean tryVless(ChannelHandlerContext ctx, byte[] data) {
        try {
            int version = data[0] & 0xFF;

            String uuid = config.getUuidWithoutDash();
            for (int i = 0; i < 16; i++) {
                int expected = Integer.parseInt(uuid.substring(i * 2, i * 2 + 2), 16);
                if ((data[i + 1] & 0xFF) != expected) {
                    return false;
                }
            }

            int addonsLen = data[17] & 0xFF;
            int offset = 19 + addonsLen;

            int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;

            int atyp = data[offset] & 0xFF;
            offset++;

            String host;
            if (atyp == 1) {
                host = String.format("%d.%d.%d.%d",
                    data[offset] & 0xFF, data[offset + 1] & 0xFF,
                    data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                offset += 4;
            } else if (atyp == 2) {
                int hostLen = data[offset] & 0xFF;
                offset++;
                host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                offset += hostLen;
            } else if (atyp == 3) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    if (i > 0) sb.append(":");
                    int val = ((data[offset + i * 2] & 0xFF) << 8) | (data[offset + i * 2 + 1] & 0xFF);
                    sb.append(Integer.toHexString(val));
                }
                host = sb.toString();
                offset += 16;
            } else {
                return false;
            }

            final int payloadOffset = offset;
            final byte[] payload = new byte[data.length - payloadOffset];
            System.arraycopy(data, payloadOffset, payload, 0, payload.length);

            ctx.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[]{(byte) version, 0})));
            connectToTarget(ctx, host, port, payload);
            return true;

        } catch (Exception e) {
            return false;
        }
    }

    private boolean tryTrojan(ChannelHandlerContext ctx, byte[] data) {
        try {
            if (data.length < 58) {
                return false;
            }

            String receivedHash = new String(data, 0, 56, StandardCharsets.UTF_8);

            MessageDigest md = MessageDigest.getInstance("SHA-224");
            byte[] hashBytes = md.digest(config.getUuid().getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            String expectedHash = sb.toString();

            if (!receivedHash.equals(expectedHash)) {
                return false;
            }

            int offset = 56;

            if (offset + 1 < data.length && data[offset] == 0x0d && data[offset + 1] == 0x0a) {
                offset += 2;
            }

            int cmd = data[offset] & 0xFF;
            if (cmd != 0x01) {
                return false;
            }
            offset++;

            int atyp = data[offset] & 0xFF;
            offset++;

            String host;
            int port;

            if (atyp == 0x01) {
                host = String.format("%d.%d.%d.%d",
                    data[offset] & 0xFF, data[offset + 1] & 0xFF,
                    data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                offset += 4;
            } else if (atyp == 0x03) {
                int hostLen = data[offset] & 0xFF;
                offset++;
                host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                offset += hostLen;
            } else if (atyp == 0x04) {
                StringBuilder ipv6 = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    if (i > 0) ipv6.append(":");
                    int val = ((data[offset + i * 2] & 0xFF) << 8) | (data[offset + i * 2 + 1] & 0xFF);
                    ipv6.append(Integer.toHexString(val));
                }
                host = ipv6.toString();
                offset += 16;
            } else {
                return false;
            }

            port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;

            if (offset + 1 < data.length && data[offset] == 0x0d && data[offset + 1] == 0x0a) {
                offset += 2;
            }

            final byte[] payload = new byte[data.length - offset];
            if (payload.length > 0) {
                System.arraycopy(data, offset, payload, 0, payload.length);
            }

            connectToTarget(ctx, host, port, payload);
            return true;

        } catch (Exception e) {
            return false;
        }
    }

    private void connectToTarget(ChannelHandlerContext ctx, String host, int port, byte[] initialPayload) {
        DnsResolver.resolve(host).thenAccept(resolvedHost -> {
            Bootstrap b = new Bootstrap();
            b.group(ctx.channel().eventLoop())
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .handler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        ch.pipeline().addLast(new RelayHandler(ctx.channel()));
                    }
                });

            b.connect(resolvedHost, port).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    outboundChannel = future.channel();
                    if (initialPayload.length > 0) {
                        outboundChannel.writeAndFlush(Unpooled.wrappedBuffer(initialPayload));
                    }
                } else {
                    ctx.close();
                }
            });
        });
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (outboundChannel != null) {
            closeOnFlush(outboundChannel);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        closeOnFlush(ctx.channel());
    }

    static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }
}
