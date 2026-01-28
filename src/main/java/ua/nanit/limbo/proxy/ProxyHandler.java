package ua.nanit.limbo.proxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import ua.nanit.limbo.server.Log;

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
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        Log.info("[WSProxy-Proxy] Handler active");
        super.channelActive(ctx);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame frame) throws Exception {
        Log.info("[WSProxy-Proxy] Received frame: %s", frame.getClass().getSimpleName());
        
        if (!(frame instanceof BinaryWebSocketFrame)) {
            Log.info("[WSProxy-Proxy] Ignoring non-binary frame");
            return;
        }

        ByteBuf buf = frame.content();
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        
        Log.info("[WSProxy-Proxy] Data length: %d, firstMessage: %b", data.length, firstMessage);

        if (firstMessage) {
            firstMessage = false;

            if (data.length > 17 && data[0] == 0) {
                Log.info("[WSProxy-Proxy] Trying VLESS...");
                if (tryVless(ctx, data)) {
                    Log.info("[WSProxy-Proxy] VLESS success");
                    return;
                }
                Log.info("[WSProxy-Proxy] VLESS failed");
            }

            Log.info("[WSProxy-Proxy] Trying Trojan...");
            if (tryTrojan(ctx, data)) {
                Log.info("[WSProxy-Proxy] Trojan success");
                return;
