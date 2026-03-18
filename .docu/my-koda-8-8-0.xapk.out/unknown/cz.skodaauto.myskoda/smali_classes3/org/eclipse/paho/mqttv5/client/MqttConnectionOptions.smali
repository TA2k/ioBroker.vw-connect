.class public Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLIENT_ID_PREFIX:Ljava/lang/String; = "paho"


# instance fields
.field private authData:[B

.field private authMethod:Ljava/lang/String;

.field private automaticReconnect:Z

.field private automaticReconnectMaxDelay:I

.field private automaticReconnectMinDelay:I

.field private cleanStart:Z

.field private connectionTimeout:I

.field private customWebSocketHeaders:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private executorServiceTimeout:I

.field private httpsHostnameVerificationEnabled:Z

.field private keepAliveInterval:I

.field private maxReconnectDelay:I

.field private maximumPacketSize:Ljava/lang/Long;

.field private mqttVersion:I

.field private password:[B

.field private receiveMaximum:Ljava/lang/Integer;

.field private requestProblemInfo:Ljava/lang/Boolean;

.field private requestResponseInfo:Ljava/lang/Boolean;

.field private sendReasonMessages:Z

.field private serverURIs:[Ljava/lang/String;

.field private sessionExpiryInterval:Ljava/lang/Long;

.field private socketFactory:Ljavax/net/SocketFactory;

.field private sslClientProps:Ljava/util/Properties;

.field private sslHostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

.field private topicAliasMaximum:Ljava/lang/Integer;

.field private useSubscriptionIdentifiers:Z

.field private userName:Ljava/lang/String;

.field private userProperties:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;"
        }
    .end annotation
.end field

.field private willDestination:Ljava/lang/String;

.field private willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

.field willMessageProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->serverURIs:[Ljava/lang/String;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnect:Z

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnectMinDelay:I

    .line 12
    .line 13
    const/16 v3, 0x78

    .line 14
    .line 15
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnectMaxDelay:I

    .line 16
    .line 17
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->useSubscriptionIdentifiers:Z

    .line 18
    .line 19
    const/16 v3, 0x3c

    .line 20
    .line 21
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->keepAliveInterval:I

    .line 22
    .line 23
    const/16 v3, 0x1e

    .line 24
    .line 25
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->connectionTimeout:I

    .line 26
    .line 27
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->httpsHostnameVerificationEnabled:Z

    .line 28
    .line 29
    const v3, 0x1f400

    .line 30
    .line 31
    .line 32
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maxReconnectDelay:I

    .line 33
    .line 34
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sendReasonMessages:Z

    .line 35
    .line 36
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 37
    .line 38
    invoke-direct {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willMessageProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 42
    .line 43
    const/4 v1, 0x5

    .line 44
    iput v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->mqttVersion:I

    .line 45
    .line 46
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->cleanStart:Z

    .line 47
    .line 48
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willDestination:Ljava/lang/String;

    .line 49
    .line 50
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 51
    .line 52
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sessionExpiryInterval:Ljava/lang/Long;

    .line 53
    .line 54
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->receiveMaximum:Ljava/lang/Integer;

    .line 55
    .line 56
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maximumPacketSize:Ljava/lang/Long;

    .line 57
    .line 58
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->topicAliasMaximum:Ljava/lang/Integer;

    .line 59
    .line 60
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestResponseInfo:Ljava/lang/Boolean;

    .line 61
    .line 62
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestProblemInfo:Ljava/lang/Boolean;

    .line 63
    .line 64
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->userProperties:Ljava/util/List;

    .line 65
    .line 66
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authMethod:Ljava/lang/String;

    .line 67
    .line 68
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authData:[B

    .line 69
    .line 70
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sslClientProps:Ljava/util/Properties;

    .line 71
    .line 72
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sslHostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 73
    .line 74
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->executorServiceTimeout:I

    .line 75
    .line 76
    return-void
.end method


# virtual methods
.method public getAuthData()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authData:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getAuthMethod()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authMethod:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getAutomaticReconnectMaxDelay()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnectMaxDelay:I

    .line 2
    .line 3
    return p0
.end method

.method public getAutomaticReconnectMinDelay()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnectMinDelay:I

    .line 2
    .line 3
    return p0
.end method

.method public getConnectionProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 2

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sessionExpiryInterval:Ljava/lang/Long;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setSessionExpiryInterval(Ljava/lang/Long;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->receiveMaximum:Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setReceiveMaximum(Ljava/lang/Integer;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maximumPacketSize:Ljava/lang/Long;

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setMaximumPacketSize(Ljava/lang/Long;)V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->topicAliasMaximum:Ljava/lang/Integer;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setTopicAliasMaximum(Ljava/lang/Integer;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestResponseInfo:Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setRequestResponseInfo(Ljava/lang/Boolean;)V

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestProblemInfo:Ljava/lang/Boolean;

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setRequestProblemInfo(Ljava/lang/Boolean;)V

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->userProperties:Ljava/util/List;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setUserProperties(Ljava/util/List;)V

    .line 39
    .line 40
    .line 41
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authMethod:Ljava/lang/String;

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setAuthenticationMethod(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authData:[B

    .line 47
    .line 48
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setAuthenticationData([B)V

    .line 49
    .line 50
    .line 51
    return-object v0
.end method

.method public getConnectionTimeout()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->connectionTimeout:I

    .line 2
    .line 3
    return p0
.end method

.method public getCustomWebSocketHeaders()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->customWebSocketHeaders:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDebug()Ljava/util/Properties;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/Properties;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/Properties;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getMqttVersion()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    const-string v2, "MqttVersion"

    .line 15
    .line 16
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const-string v2, "CleanStart"

    .line 28
    .line 29
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getConnectionTimeout()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    const-string v2, "ConTimeout"

    .line 41
    .line 42
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getKeepAliveInterval()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    const-string v2, "KeepAliveInterval"

    .line 54
    .line 55
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getUserName()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    const-string v2, "null"

    .line 63
    .line 64
    if-nez v1, :cond_0

    .line 65
    .line 66
    move-object v1, v2

    .line 67
    goto :goto_0

    .line 68
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getUserName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    :goto_0
    const-string v3, "UserName"

    .line 73
    .line 74
    invoke-virtual {v0, v3, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillDestination()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    if-nez v1, :cond_1

    .line 82
    .line 83
    move-object v1, v2

    .line 84
    goto :goto_1

    .line 85
    :cond_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillDestination()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    :goto_1
    const-string v3, "WillDestination"

    .line 90
    .line 91
    invoke-virtual {v0, v3, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSocketFactory()Ljavax/net/SocketFactory;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    const-string v3, "SocketFactory"

    .line 99
    .line 100
    if-nez v1, :cond_2

    .line 101
    .line 102
    invoke-virtual {v0, v3, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_2
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSocketFactory()Ljavax/net/SocketFactory;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-virtual {v0, v3, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    :goto_2
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSSLProperties()Ljava/util/Properties;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    const-string v3, "SSLProperties"

    .line 118
    .line 119
    if-nez v1, :cond_3

    .line 120
    .line 121
    invoke-virtual {v0, v3, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    return-object v0

    .line 125
    :cond_3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getSSLProperties()Ljava/util/Properties;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-virtual {v0, v3, p0}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    return-object v0
.end method

.method public getExecutorServiceTimeout()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->executorServiceTimeout:I

    .line 2
    .line 3
    return p0
.end method

.method public getKeepAliveInterval()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->keepAliveInterval:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxReconnectDelay()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maxReconnectDelay:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaximumPacketSize()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maximumPacketSize:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMqttVersion()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->mqttVersion:I

    .line 2
    .line 3
    return p0
.end method

.method public getPassword()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->password:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getReceiveMaximum()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->receiveMaximum:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRequestProblemInfo()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestProblemInfo:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRequestResponseInfo()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestResponseInfo:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSSLHostnameVerifier()Ljavax/net/ssl/HostnameVerifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sslHostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSSLProperties()Ljava/util/Properties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sslClientProps:Ljava/util/Properties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerURIs()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->serverURIs:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSessionExpiryInterval()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sessionExpiryInterval:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSocketFactory()Ljavax/net/SocketFactory;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->socketFactory:Ljavax/net/SocketFactory;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTopicAliasMaximum()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->topicAliasMaximum:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUserName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->userName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUserProperties()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->userProperties:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWillDestination()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willDestination:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWillMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWillMessageProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willMessageProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public isAutomaticReconnect()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnect:Z

    .line 2
    .line 3
    return p0
.end method

.method public isCleanStart()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->cleanStart:Z

    .line 2
    .line 3
    return p0
.end method

.method public isHttpsHostnameVerificationEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->httpsHostnameVerificationEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isSendReasonMessages()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sendReasonMessages:Z

    .line 2
    .line 3
    return p0
.end method

.method public setAuthData([B)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authData:[B

    .line 2
    .line 3
    return-void
.end method

.method public setAuthMethod(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->authMethod:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setAutomaticReconnect(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnect:Z

    .line 2
    .line 3
    return-void
.end method

.method public setAutomaticReconnectDelay(II)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnectMinDelay:I

    .line 2
    .line 3
    iput p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->automaticReconnectMaxDelay:I

    .line 4
    .line 5
    return-void
.end method

.method public setCleanStart(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->cleanStart:Z

    .line 2
    .line 3
    return-void
.end method

.method public setConnectionTimeout(I)V
    .locals 0

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->connectionTimeout:I

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
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
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->customWebSocketHeaders:Ljava/util/Map;

    .line 6
    .line 7
    return-void
.end method

.method public setExecutorServiceTimeout(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->executorServiceTimeout:I

    .line 2
    .line 3
    return-void
.end method

.method public setHttpsHostnameVerificationEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->httpsHostnameVerificationEnabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public setKeepAliveInterval(I)V
    .locals 0

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->keepAliveInterval:I

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public setMaxReconnectDelay(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maxReconnectDelay:I

    .line 2
    .line 3
    return-void
.end method

.method public setMaximumPacketSize(Ljava/lang/Long;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->maximumPacketSize:Ljava/lang/Long;

    .line 2
    .line 3
    return-void
.end method

.method public setPassword([B)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->password:[B

    .line 2
    .line 3
    return-void
.end method

.method public setReceiveMaximum(Ljava/lang/Integer;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const v1, 0xffff

    .line 14
    .line 15
    .line 16
    if-gt v0, v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->receiveMaximum:Ljava/lang/Integer;

    .line 26
    .line 27
    return-void
.end method

.method public setRequestProblemInfo(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestProblemInfo:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setRequestResponseInfo(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->requestResponseInfo:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setSSLHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sslHostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 2
    .line 3
    return-void
.end method

.method public setSSLProperties(Ljava/util/Properties;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sslClientProps:Ljava/util/Properties;

    .line 2
    .line 3
    return-void
.end method

.method public setSendReasonMessages(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sendReasonMessages:Z

    .line 2
    .line 3
    return-void
.end method

.method public setServerURIs([Ljava/lang/String;)V
    .locals 3

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    :goto_0
    if-lt v1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1}, [Ljava/lang/String;->clone()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, [Ljava/lang/String;

    .line 10
    .line 11
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->serverURIs:[Ljava/lang/String;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    aget-object v2, p1, v1

    .line 15
    .line 16
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModuleService;->validateURI(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    goto :goto_0
.end method

.method public setSessionExpiryInterval(Ljava/lang/Long;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->sessionExpiryInterval:Ljava/lang/Long;

    .line 2
    .line 3
    return-void
.end method

.method public setSocketFactory(Ljavax/net/SocketFactory;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->socketFactory:Ljavax/net/SocketFactory;

    .line 2
    .line 3
    return-void
.end method

.method public setTopicAliasMaximum(Ljava/lang/Integer;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xffff

    .line 8
    .line 9
    .line 10
    if-gt v0, v1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :cond_1
    :goto_0
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->topicAliasMaximum:Ljava/lang/Integer;

    .line 20
    .line 21
    return-void
.end method

.method public setUseSubscriptionIdentifiers(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->useSubscriptionIdentifiers:Z

    .line 2
    .line 3
    return-void
.end method

.method public setUserName(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->userName:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setUserProperties(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->userProperties:Ljava/util/List;

    .line 2
    .line 3
    return-void
.end method

.method public setWill(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-static {p1, v1, v0}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willDestination:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 19
    .line 20
    invoke-virtual {p2, v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setMutable(Z)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

.method public setWillMessageProperties(Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->willMessageProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getDebug()Ljava/util/Properties;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "Connection options"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpProperties(Ljava/util/Properties;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public useSubscriptionIdentifiers()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->useSubscriptionIdentifiers:Z

    .line 2
    .line 3
    return p0
.end method
