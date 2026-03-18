.class public Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;
.super Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.websocket.WebSocketSecureNetworkModule"


# instance fields
.field customWebSocketHeaders:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private host:Ljava/lang/String;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private outputStream:Ljava/io/ByteArrayOutputStream;

.field private pipedInputStream:Ljava/io/PipedInputStream;

.field private port:I

.field recievedPayload:Ljava/nio/ByteBuffer;

.field private uri:Ljava/lang/String;

.field private webSocketReceiver:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;


# direct methods
.method public constructor <init>(Ljavax/net/ssl/SSLSocketFactory;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1, p3, p4, p5}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;-><init>(Ljavax/net/ssl/SSLSocketFactory;Ljava/lang/String;ILjava/lang/String;)V

    .line 2
    .line 3
    .line 4
    const-string p1, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {p1, v0}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;

    .line 15
    .line 16
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;-><init>(Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->outputStream:Ljava/io/ByteArrayOutputStream;

    .line 20
    .line 21
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->uri:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->host:Ljava/lang/String;

    .line 24
    .line 25
    iput p4, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->port:I

    .line 26
    .line 27
    new-instance p1, Ljava/io/PipedInputStream;

    .line 28
    .line 29
    invoke-direct {p1}, Ljava/io/PipedInputStream;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->pipedInputStream:Ljava/io/PipedInputStream;

    .line 33
    .line 34
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 35
    .line 36
    invoke-interface {p0, p5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public getInputStream()Ljava/io/InputStream;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->pipedInputStream:Ljava/io/PipedInputStream;

    .line 2
    .line 3
    return-object p0
.end method

.method public getOutputStream()Ljava/io/OutputStream;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->outputStream:Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerURI()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "wss://"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->host:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ":"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->port:I

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method public getSocketInputStream()Ljava/io/InputStream;
    .locals 0

    .line 1
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->getInputStream()Ljava/io/InputStream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getSocketOutputStream()Ljava/io/OutputStream;
    .locals 0

    .line 1
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->getOutputStream()Ljava/io/OutputStream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public setCustomWebSocketHeaders(Ljava/util/Map;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->customWebSocketHeaders:Ljava/util/Map;

    .line 2
    .line 3
    return-void
.end method

.method public start()V
    .locals 7

    .line 1
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->start()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketHandshake;

    .line 5
    .line 6
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->getInputStream()Ljava/io/InputStream;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->getOutputStream()Ljava/io/OutputStream;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->uri:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->host:Ljava/lang/String;

    .line 17
    .line 18
    iget v5, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->port:I

    .line 19
    .line 20
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->customWebSocketHeaders:Ljava/util/Map;

    .line 21
    .line 22
    invoke-direct/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketHandshake;-><init>(Ljava/io/InputStream;Ljava/io/OutputStream;Ljava/lang/String;Ljava/lang/String;ILjava/util/Map;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketHandshake;->execute()V

    .line 26
    .line 27
    .line 28
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;

    .line 29
    .line 30
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->getSocketInputStream()Ljava/io/InputStream;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->pipedInputStream:Ljava/io/PipedInputStream;

    .line 35
    .line 36
    invoke-direct {v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;-><init>(Ljava/io/InputStream;Ljava/io/PipedInputStream;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->webSocketReceiver:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;

    .line 40
    .line 41
    const-string p0, "WssSocketReceiver"

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;->start(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public stop()V
    .locals 4

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;

    .line 2
    .line 3
    const-string v1, "1000"

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/16 v2, 0x8

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    invoke-direct {v0, v2, v3, v1}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;-><init>(BZ[B)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->encodeFrame()[B

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->getSocketOutputStream()Ljava/io/OutputStream;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v1, v0}, Ljava/io/OutputStream;->write([B)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->getSocketOutputStream()Ljava/io/OutputStream;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {v0}, Ljava/io/OutputStream;->flush()V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->webSocketReceiver:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;

    .line 34
    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketReceiver;->stop()V

    .line 38
    .line 39
    .line 40
    :cond_0
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->stop()V

    .line 41
    .line 42
    .line 43
    return-void
.end method
