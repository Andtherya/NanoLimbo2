package ua.nanit.limbo.proxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.extensions.compression.WebSocketServerCompressionHandler;
import ua.nanit.limbo.server.Log;

import java.net.SocketAddress;

public class ProxyServer {
    private final ProxyConfig config;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;
    private volatile boolean running = false;

    public ProxyServer(SocketAddress serverAddress) {
        this.config = new ProxyConfig(serverAddress);
    }

    public void start() {
        if (!config.isEnabled()) {
            Log.info("[WSProxy] Proxy server is disabled");
            return;
        }

        if (config.getUuid().isEmpty()) {
            Log.warning("[WSProxy] UUID not configured, proxy server disabled");
            return;
        }

        if (running) {
            return;
        }

        GeoIPService.fetchISP();

        new Thread(() -> {
            try {
                bossGroup = new NioEventLoopGroup(1);
                workerGroup = new NioEventLoopGroup();

                ServerBootstrap b = new ServerBootstrap();
                b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();
                            p.addLast(new HttpServerCodec());
                            p.addLast(new HttpObjectAggregator(65536));
                            p.addLast(new WebSocketServerCompressionHandler());
                            p.addLast(new HttpRequestHandler(config));
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);

                serverChannel = b.bind(config.getPort()).sync().channel();
                running = true;
                Log.info("[WSProxy] Proxy server started on port %d", config.getPort());
                serverChannel.closeFuture().sync();
            } catch (Exception e) {
                Log.error("[WSProxy] Failed to start: %s", e.getMessage());
            } finally {
                running = false;
                shutdown();
            }
        }, "WSProxy-Server").start();
    }

    public void stop() {
        running = false;
        if (serverChannel != null) {
            serverChannel.close();
        }
        shutdown();
        Log.info("[WSProxy] Proxy server stopped");
    }

    private void shutdown() {
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
    }

    public boolean isRunning() {
        return running;
    }
}
