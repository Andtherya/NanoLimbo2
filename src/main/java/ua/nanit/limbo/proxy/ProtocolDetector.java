package ua.nanit.limbo.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.extensions.compression.WebSocketServerCompressionHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;
import ua.nanit.limbo.connection.ClientConnection;
import ua.nanit.limbo.connection.pipeline.*;
import ua.nanit.limbo.server.LimboServer;
import ua.nanit.limbo.server.Log;

import java.util.concurrent.TimeUnit;

public class ProtocolDetector extends ChannelInboundHandlerAdapter {

    private final LimboServer server;
    private final ProxyConfig proxyConfig;

    public ProtocolDetector(LimboServer server, ProxyConfig proxyConfig) {
        this.server = server;
        this.proxyConfig = proxyConfig;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        Log.info("[WSProxy] New connection from: %s", ctx.channel().remoteAddress());
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        Log.info("[WSProxy] channelRead called, msg type: %s", msg.getClass().getSimpleName());
        
        if (!(msg instanceof ByteBuf)) {
            ctx.fireChannelRead(msg);
            return;
        }

        ByteBuf buf = (ByteBuf) msg;
        if (buf.readableBytes() < 1) {
            ctx.fireChannelRead(msg);
            return;
        }

        int firstByte = buf.getUnsignedByte(buf.readerIndex());
        ChannelPipeline pipeline = ctx.pipeline();

        Log.info("[WSProxy] First byte: %d ('%c'), readable: %d", firstByte, (char) firstByte, buf.readableBytes());

        // 先移除自己
        pipeline.remove(this);

        if (isHttp(firstByte)) {
            Log.info("[WSProxy] Switching to HTTP mode");
            // HTTP/WebSocket处理
            pipeline.addLast("http_codec", new HttpServerCodec());
            pipeline.addLast("http_aggregator", new HttpObjectAggregator(65536));
            pipeline.addLast("ws_compression", new WebSocketServerCompressionHandler());
            pipeline.addLast("http_handler", new HttpRequestHandler(proxyConfig));
        } else {
            Log.info("[WSProxy] Switching to Minecraft mode");
            // Minecraft协议处理
            PacketDecoder decoder = new PacketDecoder();
            PacketEncoder encoder = new PacketEncoder();
            ClientConnection connection = new ClientConnection(ctx.channel(), server, decoder, encoder);

            pipeline.addLast("timeout", new ReadTimeoutHandler(server.getConfig().getReadTimeout(), TimeUnit.MILLISECONDS));
            pipeline.addLast("frame_decoder", new VarIntFrameDecoder());
            pipeline.addLast("frame_encoder", new VarIntLengthEncoder());

            if (server.getConfig().isUseTrafficLimits()) {
                pipeline.addLast("traffic_limit", new ChannelTrafficHandler(
                    server.getConfig().getMaxPacketSize(),
                    server.getConfig().getInterval(),
                    server.getConfig().getMaxPacketRate()
                ));
            }

            pipeline.addLast("decoder", decoder);
            pipeline.addLast("encoder", encoder);
            pipeline.addLast("handler", connection);
        }

        // 把数据传递给新添加的handler
        ctx.fireChannelRead(msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        Log.error("[WSProxy] Exception: %s", cause.getMessage());
        ctx.close();
    }

    private boolean isHttp(int firstByte) {
        return firstByte == 'G' || firstByte == 'P' || firstByte == 'H' ||
               firstByte == 'D' || firstByte == 'O' || firstByte == 'C' || firstByte == 'T';
    }
}
