package ua.nanit.limbo.proxy;

import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.util.CharsetUtil;

import java.util.Base64;

public class HttpRequestHandler extends SimpleChannelInboundHandler<Object> {
    private final ProxyConfig config;
    private WebSocketServerHandshaker handshaker;

    public HttpRequestHandler(ProxyConfig config) {
        this.config = config;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof FullHttpRequest) {
            handleHttpRequest(ctx, (FullHttpRequest) msg);
        } else if (msg instanceof WebSocketFrame) {
            handleWebSocketFrame(ctx, (WebSocketFrame) msg);
        }
    }

    private void handleHttpRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (req.headers().contains(HttpHeaderNames.UPGRADE, HttpHeaderValues.WEBSOCKET, true)) {
            WebSocketServerHandshakerFactory wsFactory = new WebSocketServerHandshakerFactory(
                getWebSocketLocation(req), null, true, 65536);
            handshaker = wsFactory.newHandshaker(req);
            if (handshaker == null) {
                WebSocketServerHandshakerFactory.sendUnsupportedVersionResponse(ctx.channel());
            } else {
                handshaker.handshake(ctx.channel(), req).addListener(future -> {
                    if (future.isSuccess()) {
                        ctx.pipeline().addLast(new ProxyHandler(config));
                    }
                });
            }
            return;
        }

        String uri = req.uri();
        FullHttpResponse response;

        if ("/".equals(uri)) {
            response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                Unpooled.copiedBuffer("This is a Discord bot endpoint. Access denied.", CharsetUtil.UTF_8));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
        } else if (("/" + config.getSubPath()).equals(uri)) {
            String subscription = buildSubscription();
            String base64Content = Base64.getEncoder().encodeToString(subscription.getBytes());
            response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                Unpooled.copiedBuffer(base64Content + "\n", CharsetUtil.UTF_8));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
        } else {
            response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND,
                Unpooled.copiedBuffer("Not Found\n", CharsetUtil.UTF_8));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
        }

        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    private String buildSubscription() {
        String isp = GeoIPService.getISP();
        String namePart = config.getName().isEmpty() ? isp : config.getName() + "-" + isp;

        String vlessURL = String.format(
            "vless://%s@cdns.doon.eu.org:443?encryption=none&security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2F%s#%s",
            config.getUuid(), config.getDomain(), config.getDomain(), config.getWsPath(), namePart);

        String trojanURL = String.format(
            "trojan://%s@cdns.doon.eu.org:443?security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2F%s#%s",
            config.getUuid(), config.getDomain(), config.getDomain(), config.getWsPath(), namePart);

        return vlessURL + "\n" + trojanURL;
    }

    private void handleWebSocketFrame(ChannelHandlerContext ctx, WebSocketFrame frame) {
        if (frame instanceof CloseWebSocketFrame) {
            handshaker.close(ctx.channel(), (CloseWebSocketFrame) frame.retain());
            return;
        }
        if (frame instanceof PingWebSocketFrame) {
            ctx.channel().write(new PongWebSocketFrame(frame.content().retain()));
            return;
        }
        ctx.fireChannelRead(frame.retain());
    }

    private String getWebSocketLocation(FullHttpRequest req) {
        return "ws://" + req.headers().get(HttpHeaderNames.HOST) + req.uri();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.close();
    }
}
