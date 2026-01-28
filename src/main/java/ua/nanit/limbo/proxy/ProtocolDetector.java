package ua.nanit.limbo.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.extensions.compression.WebSocketServerCompressionHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;
import ua.nanit.limbo.connection.ClientConnection;
import ua.nanit.limbo.connection.pipeline.*;
import ua.nanit.limbo.server.LimboServer;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class ProtocolDetector extends ByteToMessageDecoder {

    private final LimboServer server;
    private final ProxyConfig proxyConfig;

    public ProtocolDetector(LimboServer server, ProxyConfig proxyConfig) {
        this.server = server;
        this.proxyConfig = proxyConfig;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (in.readableBytes() < 1) {
            return;
        }

        int firstByte = in.getUnsignedByte(in.readerIndex());
        ChannelPipeline pipeline = ctx.pipeline();

        // HTTP请求以 G(GET), P(POST/PUT), H(HEAD), D(DELETE), O(OPTIONS), C(CONNECT) 开头
        // 或者WebSocket升级请求
        if (isHttp(firstByte)) {
            // 切换到HTTP/WebSocket处理
            pipeline.addLast("http_codec", new HttpServerCodec());
            pipeline.addLast("http_aggregator", new HttpObjectAggregator(65536));
            pipeline.addLast("ws_compression", new WebSocketServerCompressionHandler());
            pipeline.addLast("http_handler", new HttpRequestHandler(proxyConfig));
        } else {
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

        // 移除协议检测器
        pipeline.remove(this);
    }

    private boolean isHttp(int firstByte) {
        // HTTP方法的首字母: G(71), P(80), H(72), D(68), O(79), C(67), T(84)
        return firstByte == 'G' || firstByte == 'P' || firstByte == 'H' ||
               firstByte == 'D' || firstByte == 'O' || firstByte == 'C' || firstByte == 'T';
    }
}
