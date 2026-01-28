package ua.nanit.limbo.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;

public class RelayHandler extends ChannelInboundHandlerAdapter {
    private final Channel inboundChannel;

    public RelayHandler(Channel inboundChannel) {
        this.inboundChannel = inboundChannel;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.read();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (inboundChannel.isActive()) {
            ByteBuf buf = (ByteBuf) msg;
            inboundChannel.writeAndFlush(new BinaryWebSocketFrame(buf)).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    ctx.channel().read();
                } else {
                    future.channel().close();
                }
            });
        } else {
            ((ByteBuf) msg).release();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        ProxyHandler.closeOnFlush(inboundChannel);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ProxyHandler.closeOnFlush(ctx.channel());
    }
}
