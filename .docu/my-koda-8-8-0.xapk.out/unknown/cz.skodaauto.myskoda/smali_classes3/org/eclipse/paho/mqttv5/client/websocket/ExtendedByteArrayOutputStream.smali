.class Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;
.super Ljava/io/ByteArrayOutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field final webSocketNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;

.field final webSocketSecureNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 2
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->webSocketNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;

    const/4 p1, 0x0

    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->webSocketSecureNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;

    return-void
.end method

.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;)V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->webSocketNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;

    .line 6
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->webSocketSecureNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;

    return-void
.end method


# virtual methods
.method public flush()V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    invoke-static {v0}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->reset()V

    .line 11
    .line 12
    .line 13
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const/4 v3, 0x2

    .line 22
    invoke-direct {v1, v3, v2, v0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;-><init>(BZ[B)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->encodeFrame()[B

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->getSocketOutputStream()Ljava/io/OutputStream;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v1, v0}, Ljava/io/OutputStream;->write([B)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->getSocketOutputStream()Ljava/io/OutputStream;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {p0}, Ljava/io/OutputStream;->flush()V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    throw v0
.end method

.method public getSocketOutputStream()Ljava/io/OutputStream;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->webSocketNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;->getSocketOutputStream()Ljava/io/OutputStream;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/ExtendedByteArrayOutputStream;->webSocketSecureNetworkModule:Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;

    .line 11
    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->getSocketOutputStream()Ljava/io/OutputStream;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_1
    const/4 p0, 0x0

    .line 20
    return-object p0
.end method
