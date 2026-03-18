.class public Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModuleFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/spi/NetworkModuleFactory;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public createNetworkModule(Ljava/net/URI;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;
    .locals 6

    .line 1
    invoke-virtual {p1}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v3

    .line 5
    invoke-virtual {p1}, Ljava/net/URI;->getPort()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const/4 v0, -0x1

    .line 10
    if-ne p0, v0, :cond_0

    .line 11
    .line 12
    const/16 p0, 0x50

    .line 13
    .line 14
    :cond_0
    move v4, p0

    .line 15
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSocketFactory()Ljavax/net/SocketFactory;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    if-nez p0, :cond_1

    .line 20
    .line 21
    invoke-static {}, Ljavax/net/SocketFactory;->getDefault()Ljavax/net/SocketFactory;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :goto_0
    move-object v1, p0

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    instance-of v0, p0, Ljavax/net/ssl/SSLSocketFactory;

    .line 28
    .line 29
    if-nez v0, :cond_2

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :goto_1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    move-object v5, p3

    .line 39
    invoke-direct/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;-><init>(Ljavax/net/SocketFactory;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getConnectionTimeout()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->setConnectTimeout(I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getCustomWebSocketHeaders()Ljava/util/Map;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketNetworkModule;->setCustomWebSocketHeaders(Ljava/util/Map;)V

    .line 54
    .line 55
    .line 56
    return-object v0

    .line 57
    :cond_2
    const/16 p0, 0x7d69

    .line 58
    .line 59
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    throw p0
.end method

.method public getSupportedUriSchemes()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/util/HashSet;

    .line 2
    .line 3
    const-string v0, "ws"

    .line 4
    .line 5
    filled-new-array {v0}, [Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-direct {p0, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public validateURI(Ljava/net/URI;)V
    .locals 0

    .line 1
    return-void
.end method
