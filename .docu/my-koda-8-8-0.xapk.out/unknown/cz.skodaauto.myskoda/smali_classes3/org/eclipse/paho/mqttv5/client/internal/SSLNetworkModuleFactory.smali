.class public Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModuleFactory;
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
    .locals 5

    .line 1
    invoke-virtual {p1}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p1}, Ljava/net/URI;->getPort()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, -0x1

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    const/16 v0, 0x22b3

    .line 13
    .line 14
    :cond_0
    invoke-virtual {p1}, Ljava/net/URI;->getPath()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_2
    :goto_0
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSocketFactory()Ljavax/net/SocketFactory;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    const/4 v1, 0x0

    .line 42
    if-nez p1, :cond_4

    .line 43
    .line 44
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;

    .line 45
    .line 46
    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;-><init>()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSSLProperties()Ljava/util/Properties;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    if-eqz v2, :cond_3

    .line 54
    .line 55
    invoke-virtual {p1, v2, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->initialize(Ljava/util/Properties;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    :cond_3
    invoke-virtual {p1, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->createSocketFactory(Ljava/lang/String;)Ljavax/net/ssl/SSLSocketFactory;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    move-object v4, v2

    .line 63
    move-object v2, p1

    .line 64
    move-object p1, v4

    .line 65
    goto :goto_1

    .line 66
    :cond_4
    instance-of v2, p1, Ljavax/net/ssl/SSLSocketFactory;

    .line 67
    .line 68
    if-eqz v2, :cond_6

    .line 69
    .line 70
    move-object v2, v1

    .line 71
    :goto_1
    new-instance v3, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;

    .line 72
    .line 73
    check-cast p1, Ljavax/net/ssl/SSLSocketFactory;

    .line 74
    .line 75
    invoke-direct {v3, p1, p0, v0, p3}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;-><init>(Ljavax/net/ssl/SSLSocketFactory;Ljava/lang/String;ILjava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getConnectionTimeout()I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    invoke-virtual {v3, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setSSLhandshakeTimeout(I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSSLHostnameVerifier()Ljavax/net/ssl/HostnameVerifier;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {v3, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setSSLHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isHttpsHostnameVerificationEnabled()Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    invoke-virtual {v3, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setHttpsHostnameVerificationEnabled(Z)V

    .line 97
    .line 98
    .line 99
    if-eqz v2, :cond_5

    .line 100
    .line 101
    invoke-virtual {v2, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getEnabledCipherSuites(Ljava/lang/String;)[Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-eqz p0, :cond_5

    .line 106
    .line 107
    invoke-virtual {v3, p0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setEnabledCiphers([Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    :cond_5
    return-object v3

    .line 111
    :cond_6
    const/16 p0, 0x7d69

    .line 112
    .line 113
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
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
    const-string v0, "ssl"

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
    invoke-virtual {p1}, Ljava/net/URI;->getPath()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    :goto_0
    return-void
.end method
