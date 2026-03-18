.class public Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttActionListener;


# instance fields
.field private client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

.field private comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

.field private mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

.field private mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

.field private options:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

.field private persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

.field private reconnect:Z

.field private userCallback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

.field private userContext:Ljava/lang/Object;

.field private userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Lorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ZLorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 5
    .line 6
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 7
    .line 8
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 9
    .line 10
    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->options:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 11
    .line 12
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 13
    .line 14
    iput-object p6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userContext:Ljava/lang/Object;

    .line 15
    .line 16
    iput-object p7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userCallback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 17
    .line 18
    iput-boolean p8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->reconnect:Z

    .line 19
    .line 20
    iput-object p9, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 21
    .line 22
    iput-object p10, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public connect()V
    .locals 3

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 4
    .line 5
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 19
    .line 20
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    const-string v2, ""

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_0

    .line 31
    .line 32
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 33
    .line 34
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 35
    .line 36
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-interface {v1, v2}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->open(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->options:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 44
    .line 45
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_0

    .line 50
    .line 51
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 52
    .line 53
    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->clear()V

    .line 54
    .line 55
    .line 56
    :cond_0
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 57
    .line 58
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->options:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 59
    .line 60
    invoke-virtual {v1, v2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :catch_0
    move-exception v1

    .line 65
    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method

.method public onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getNetworkModules()[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    array-length v0, v0

    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 9
    .line 10
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getNetworkModuleIndex()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    add-int/lit8 v1, v1, 0x1

    .line 15
    .line 16
    if-ge v1, v0, :cond_0

    .line 17
    .line 18
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 19
    .line 20
    invoke-virtual {p2, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setNetworkModuleIndex(I)V

    .line 21
    .line 22
    .line 23
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->connect()V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :catch_0
    move-exception p2

    .line 28
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    instance-of p1, p2, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 33
    .line 34
    if-eqz p1, :cond_1

    .line 35
    .line 36
    move-object p1, p2

    .line 37
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 41
    .line 42
    invoke-direct {p1, p2}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 43
    .line 44
    .line 45
    :goto_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 46
    .line 47
    iget-object v0, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 48
    .line 49
    const/4 v1, 0x0

    .line 50
    invoke-virtual {v0, v1, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 54
    .line 55
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 56
    .line 57
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifyComplete()V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 61
    .line 62
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 63
    .line 64
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V

    .line 67
    .line 68
    .line 69
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userCallback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 70
    .line 71
    if-eqz p1, :cond_2

    .line 72
    .line 73
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 74
    .line 75
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userContext:Ljava/lang/Object;

    .line 76
    .line 77
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userCallback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 81
    .line 82
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 83
    .line 84
    invoke-interface {p1, p0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttActionListener;->onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V

    .line 85
    .line 86
    .line 87
    :cond_2
    return-void
.end method

.method public onSuccess(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V
    .locals 4

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 3
    .line 4
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 11
    .line 12
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getReceiveMaximum()Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setReceiveMaximum(Ljava/lang/Integer;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 24
    .line 25
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getMaximumQoS()Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setMaximumQoS(Ljava/lang/Integer;)V

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 37
    .line 38
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->isRetainAvailable()Ljava/lang/Boolean;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setRetainAvailable(Ljava/lang/Boolean;)V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 50
    .line 51
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getMaximumPacketSize()Ljava/lang/Long;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setOutgoingMaximumPacketSize(Ljava/lang/Long;)V

    .line 60
    .line 61
    .line 62
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 63
    .line 64
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->options:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 65
    .line 66
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getMaximumPacketSize()Ljava/lang/Long;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setIncomingMaximumPacketSize(Ljava/lang/Long;)V

    .line 71
    .line 72
    .line 73
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 74
    .line 75
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAliasMaximum()Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setOutgoingTopicAliasMaximum(Ljava/lang/Integer;)V

    .line 84
    .line 85
    .line 86
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 87
    .line 88
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->isWildcardSubscriptionsAvailable()Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setWildcardSubscriptionsAvailable(Ljava/lang/Boolean;)V

    .line 101
    .line 102
    .line 103
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 104
    .line 105
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->isSubscriptionIdentifiersAvailable()Z

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setSubscriptionIdentifiersAvailable(Ljava/lang/Boolean;)V

    .line 118
    .line 119
    .line 120
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 121
    .line 122
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->isSharedSubscriptionAvailable()Z

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setSharedSubscriptionsAvailable(Ljava/lang/Boolean;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getServerKeepAlive()Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    if-eqz v1, :cond_0

    .line 146
    .line 147
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 148
    .line 149
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getServerKeepAlive()Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 158
    .line 159
    .line 160
    move-result v2

    .line 161
    int-to-long v2, v2

    .line 162
    invoke-virtual {v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setKeepAliveSeconds(J)V

    .line 163
    .line 164
    .line 165
    :cond_0
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 166
    .line 167
    .line 168
    move-result-object v1

    .line 169
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getAssignedClientIdentifier()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    if-eqz v1, :cond_1

    .line 174
    .line 175
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 176
    .line 177
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getAssignedClientIdentifier()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->setClientId(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 189
    .line 190
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getAssignedClientIdentifier()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    invoke-interface {v1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->open(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->options:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 202
    .line 203
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    .line 204
    .line 205
    .line 206
    move-result v0

    .line 207
    if-eqz v0, :cond_1

    .line 208
    .line 209
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 210
    .line 211
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->clear()V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 212
    .line 213
    .line 214
    goto :goto_0

    .line 215
    :catch_0
    move-exception v0

    .line 216
    :try_start_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 217
    .line 218
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnect()Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    :try_end_1
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_1 .. :try_end_1} :catch_1

    .line 219
    .line 220
    .line 221
    :catch_1
    invoke-virtual {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V

    .line 222
    .line 223
    .line 224
    return-void

    .line 225
    :cond_1
    :goto_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 226
    .line 227
    iget-object v0, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 228
    .line 229
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->getResponse()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    const/4 v1, 0x0

    .line 234
    invoke-virtual {v0, p1, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 235
    .line 236
    .line 237
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 238
    .line 239
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 240
    .line 241
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifyComplete()V

    .line 242
    .line 243
    .line 244
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 245
    .line 246
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 247
    .line 248
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 249
    .line 250
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V

    .line 251
    .line 252
    .line 253
    iget-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->reconnect:Z

    .line 254
    .line 255
    if-eqz p1, :cond_2

    .line 256
    .line 257
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 258
    .line 259
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->notifyReconnect()V

    .line 260
    .line 261
    .line 262
    :cond_2
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userCallback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 263
    .line 264
    if-eqz p1, :cond_3

    .line 265
    .line 266
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 267
    .line 268
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userContext:Ljava/lang/Object;

    .line 269
    .line 270
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userCallback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 274
    .line 275
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->userToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 276
    .line 277
    invoke-interface {p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttActionListener;->onSuccess(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V

    .line 278
    .line 279
    .line 280
    :cond_3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 281
    .line 282
    if-eqz p1, :cond_4

    .line 283
    .line 284
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 285
    .line 286
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getNetworkModules()[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 287
    .line 288
    .line 289
    move-result-object p1

    .line 290
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 291
    .line 292
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getNetworkModuleIndex()I

    .line 293
    .line 294
    .line 295
    move-result v0

    .line 296
    aget-object p1, p1, v0

    .line 297
    .line 298
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;->getServerURI()Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object p1

    .line 302
    :try_start_2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 303
    .line 304
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->reconnect:Z

    .line 305
    .line 306
    invoke-interface {v0, p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->connectComplete(ZLjava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 307
    .line 308
    .line 309
    :catchall_0
    :cond_4
    return-void
.end method

.method public setMqttCallbackExtended(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 2
    .line 3
    return-void
.end method
