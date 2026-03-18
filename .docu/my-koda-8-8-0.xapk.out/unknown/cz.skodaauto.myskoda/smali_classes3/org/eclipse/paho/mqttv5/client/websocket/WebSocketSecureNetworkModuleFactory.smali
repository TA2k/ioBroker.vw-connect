.class public Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModuleFactory;
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
    .locals 8

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
    const/16 p0, 0x1bb

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
    const/4 v6, 0x0

    .line 20
    if-nez p0, :cond_2

    .line 21
    .line 22
    new-instance p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;

    .line 23
    .line 24
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;-><init>()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSSLProperties()Ljava/util/Properties;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0, v0, v6}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->initialize(Ljava/util/Properties;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    invoke-virtual {p0, v6}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->createSocketFactory(Ljava/lang/String;)Ljavax/net/ssl/SSLSocketFactory;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    move-object v7, p0

    .line 41
    move-object p0, v0

    .line 42
    goto :goto_0

    .line 43
    :cond_2
    instance-of v0, p0, Ljavax/net/ssl/SSLSocketFactory;

    .line 44
    .line 45
    if-eqz v0, :cond_4

    .line 46
    .line 47
    move-object v7, v6

    .line 48
    :goto_0
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;

    .line 49
    .line 50
    move-object v1, p0

    .line 51
    check-cast v1, Ljavax/net/ssl/SSLSocketFactory;

    .line 52
    .line 53
    invoke-virtual {p1}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    move-object v5, p3

    .line 58
    invoke-direct/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;-><init>(Ljavax/net/ssl/SSLSocketFactory;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getConnectionTimeout()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setSSLhandshakeTimeout(I)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSSLHostnameVerifier()Ljavax/net/ssl/HostnameVerifier;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setSSLHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isHttpsHostnameVerificationEnabled()Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setHttpsHostnameVerificationEnabled(Z)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getCustomWebSocketHeaders()Ljava/util/Map;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketSecureNetworkModule;->setCustomWebSocketHeaders(Ljava/util/Map;)V

    .line 87
    .line 88
    .line 89
    if-eqz v7, :cond_3

    .line 90
    .line 91
    invoke-virtual {v7, v6}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getEnabledCipherSuites(Ljava/lang/String;)[Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    if-eqz p0, :cond_3

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setEnabledCiphers([Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    :cond_3
    return-object v0

    .line 101
    :cond_4
    const/16 p0, 0x7d69

    .line 102
    .line 103
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
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
    const-string v0, "wss"

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
