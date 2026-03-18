.class public Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;,
        Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;,
        Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;
    }
.end annotation


# static fields
.field public static BUILD_LEVEL:Ljava/lang/String; = "L${build.level}"

.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.ClientComms"

.field private static final CLOSED:B = 0x4t

.field private static final CONNECTED:B = 0x0t

.field private static final CONNECTING:B = 0x1t

.field private static final DISCONNECTED:B = 0x3t

.field private static final DISCONNECTING:B = 0x2t

.field public static VERSION:Ljava/lang/String; = "${project.version}"


# instance fields
.field private callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

.field private client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

.field private clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

.field private closePending:Z

.field private final conLock:Ljava/lang/Object;

.field private conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

.field private conState:B

.field private disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

.field private executorService:Ljava/util/concurrent/ExecutorService;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

.field private networkModuleIndex:I

.field private networkModules:[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

.field private persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

.field private pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

.field private receiver:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

.field private resting:Z

.field private sender:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

.field private stoppingComms:Z

.field private tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Ljava/util/concurrent/ExecutorService;Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string p5, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {p5, v0}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object p5

    .line 12
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    const/4 p5, 0x0

    .line 15
    iput-boolean p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->stoppingComms:Z

    .line 16
    .line 17
    new-instance v0, Ljava/lang/Object;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 23
    .line 24
    iput-boolean p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->closePending:Z

    .line 25
    .line 26
    iput-boolean p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->resting:Z

    .line 27
    .line 28
    const/4 p5, 0x3

    .line 29
    iput-byte p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 30
    .line 31
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 32
    .line 33
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 34
    .line 35
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 36
    .line 37
    invoke-interface {p3, p0}, Lorg/eclipse/paho/mqttv5/client/MqttPingSender;->init(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V

    .line 38
    .line 39
    .line 40
    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 41
    .line 42
    iput-object p6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 43
    .line 44
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 45
    .line 46
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 47
    .line 48
    .line 49
    move-result-object p4

    .line 50
    invoke-interface {p4}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p4

    .line 54
    invoke-direct {p1, p4}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 58
    .line 59
    new-instance v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 60
    .line 61
    invoke-direct {v3, p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V

    .line 62
    .line 63
    .line 64
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 65
    .line 66
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 67
    .line 68
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 69
    .line 70
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 71
    .line 72
    move-object v4, p0

    .line 73
    move-object v1, p2

    .line 74
    move-object v5, p3

    .line 75
    invoke-direct/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;)V

    .line 76
    .line 77
    .line 78
    iput-object v0, v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 79
    .line 80
    iget-object p0, v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 81
    .line 82
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->setClientState(Lorg/eclipse/paho/mqttv5/client/internal/ClientState;)V

    .line 83
    .line 84
    .line 85
    iget-object p0, v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 86
    .line 87
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-interface {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    return-void
.end method

.method public static synthetic access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$1(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sender:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$11(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$2()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$3(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$4(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModules:[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$5(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModuleIndex:I

    .line 2
    .line 3
    return p0
.end method

.method public static synthetic access$6(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/ClientState;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$7(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->receiver:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 2
    .line 3
    return-void
.end method

.method public static synthetic access$8(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->receiver:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$9(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sender:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 2
    .line 3
    return-void
.end method

.method private handleOldTokens(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "handleOldTokens"

    .line 6
    .line 7
    const-string v3, "222"

    .line 8
    .line 9
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 16
    .line 17
    iget-object v2, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 18
    .line 19
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getToken(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 30
    .line 31
    iget-object v2, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 32
    .line 33
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v1, p1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 41
    .line 42
    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->resolveOldTokens(Lorg/eclipse/paho/mqttv5/common/MqttException;)Ljava/util/Vector;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-virtual {p1}, Ljava/util/Vector;->elements()Ljava/util/Enumeration;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    :goto_0
    invoke-interface {p1}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    if-nez p2, :cond_1

    .line 55
    .line 56
    return-object v0

    .line 57
    :cond_1
    invoke-interface {p1}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    check-cast p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 62
    .line 63
    iget-object v1, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 64
    .line 65
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    const-string v2, "Disc"

    .line 70
    .line 71
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_3

    .line 76
    .line 77
    iget-object v1, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 78
    .line 79
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    const-string v2, "Con"

    .line 84
    .line 85
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-eqz v1, :cond_2

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 93
    .line 94
    invoke-virtual {v1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->asyncOperationComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_3
    :goto_1
    move-object v0, p2

    .line 99
    goto :goto_0

    .line 100
    :catch_0
    return-object v0
.end method

.method private handleRunException(Ljava/lang/Exception;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v3, "804"

    .line 6
    .line 7
    const/4 v4, 0x0

    .line 8
    const-string v2, "handleRunException"

    .line 9
    .line 10
    move-object v5, p1

    .line 11
    invoke-interface/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 12
    .line 13
    .line 14
    instance-of p1, v5, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 15
    .line 16
    if-nez p1, :cond_0

    .line 17
    .line 18
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 19
    .line 20
    const/16 v0, 0x7d6d

    .line 21
    .line 22
    invoke-direct {p1, v0, v5}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILjava/lang/Throwable;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move-object p1, v5

    .line 27
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 28
    .line 29
    :goto_0
    const/4 v0, 0x0

    .line 30
    invoke-virtual {p0, v0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public checkForActivity()Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->checkForActivity(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    move-result-object p0

    return-object p0
.end method

.method public checkForActivity(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 1

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkForActivity(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    move-result-object p0
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p1

    goto :goto_0

    :catch_1
    move-exception p1

    goto :goto_1

    .line 3
    :goto_0
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->handleRunException(Ljava/lang/Exception;)V

    goto :goto_2

    .line 4
    :goto_1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->handleRunException(Ljava/lang/Exception;)V

    :goto_2
    const/4 p0, 0x0

    return-object p0
.end method

.method public close(Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isClosed()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-nez v1, :cond_4

    .line 9
    .line 10
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnected()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    :cond_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 19
    .line 20
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 21
    .line 22
    const-string v2, "close"

    .line 23
    .line 24
    const-string v3, "224"

    .line 25
    .line 26
    invoke-interface {p1, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnecting()Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-nez p1, :cond_3

    .line 34
    .line 35
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_2

    .line 40
    .line 41
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eqz p1, :cond_1

    .line 46
    .line 47
    const/4 p1, 0x1

    .line 48
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->closePending:Z

    .line 49
    .line 50
    monitor-exit v0

    .line 51
    return-void

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    const/4 p1, 0x4

    .line 55
    iput-byte p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 56
    .line 57
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 58
    .line 59
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->close()V

    .line 60
    .line 61
    .line 62
    const/4 p1, 0x0

    .line 63
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 64
    .line 65
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 66
    .line 67
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 68
    .line 69
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sender:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 70
    .line 71
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 72
    .line 73
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->receiver:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 74
    .line 75
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModules:[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 76
    .line 77
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 78
    .line 79
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_2
    const/16 p0, 0x7d64

    .line 83
    .line 84
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    throw p0

    .line 89
    :cond_3
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 90
    .line 91
    const/16 p1, 0x7d6e

    .line 92
    .line 93
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_4
    :goto_0
    monitor-exit v0

    .line 98
    return-void

    .line 99
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 100
    throw p0
.end method

.method public connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 9

    .line 1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnected()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_4

    .line 9
    .line 10
    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->closePending:Z

    .line 11
    .line 12
    if-nez v0, :cond_4

    .line 13
    .line 14
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 15
    .line 16
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 17
    .line 18
    const-string v3, "connect"

    .line 19
    .line 20
    const-string v4, "214"

    .line 21
    .line 22
    invoke-interface {v0, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    iput-byte v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 27
    .line 28
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 29
    .line 30
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 31
    .line 32
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 33
    .line 34
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 39
    .line 40
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getMqttVersion()I

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 45
    .line 46
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 51
    .line 52
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getKeepAliveInterval()I

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 57
    .line 58
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getConnectionProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 59
    .line 60
    .line 61
    move-result-object v7

    .line 62
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 63
    .line 64
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillMessageProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    invoke-direct/range {v2 .. v8}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;-><init>(Ljava/lang/String;IZILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 69
    .line 70
    .line 71
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 72
    .line 73
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillDestination()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-eqz p1, :cond_0

    .line 78
    .line 79
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 80
    .line 81
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillDestination()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {v2, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->setWillDestination(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :catchall_0
    move-exception v0

    .line 90
    move-object p0, v0

    .line 91
    goto/16 :goto_1

    .line 92
    .line 93
    :cond_0
    :goto_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 94
    .line 95
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    if-eqz p1, :cond_1

    .line 100
    .line 101
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 102
    .line 103
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    invoke-virtual {v2, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->setWillMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 108
    .line 109
    .line 110
    :cond_1
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 111
    .line 112
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getUserName()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    if-eqz p1, :cond_2

    .line 117
    .line 118
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 119
    .line 120
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getUserName()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-virtual {v2, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->setUserName(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    :cond_2
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 128
    .line 129
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getPassword()[B

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-eqz p1, :cond_3

    .line 134
    .line 135
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 136
    .line 137
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getPassword()[B

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    invoke-virtual {v2, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->setPassword([B)V

    .line 142
    .line 143
    .line 144
    :cond_3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 145
    .line 146
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 147
    .line 148
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getKeepAliveInterval()I

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    int-to-long v3, v0

    .line 153
    invoke-virtual {p1, v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setKeepAliveSeconds(J)V

    .line 154
    .line 155
    .line 156
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 157
    .line 158
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 159
    .line 160
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->setCleanStart(Z)V

    .line 165
    .line 166
    .line 167
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 168
    .line 169
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->open()V

    .line 170
    .line 171
    .line 172
    move-object v6, v2

    .line 173
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;

    .line 174
    .line 175
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 176
    .line 177
    move-object v4, p0

    .line 178
    move-object v3, p0

    .line 179
    move-object v5, p2

    .line 180
    invoke-direct/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;Ljava/util/concurrent/ExecutorService;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->start()V

    .line 184
    .line 185
    .line 186
    monitor-exit v1

    .line 187
    return-void

    .line 188
    :cond_4
    move-object v3, p0

    .line 189
    iget-object p0, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 190
    .line 191
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 192
    .line 193
    const-string p2, "connect"

    .line 194
    .line 195
    const-string v0, "207"

    .line 196
    .line 197
    iget-byte v2, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 198
    .line 199
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    invoke-interface {p0, p1, p2, v0, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isClosed()Z

    .line 211
    .line 212
    .line 213
    move-result p0

    .line 214
    if-nez p0, :cond_7

    .line 215
    .line 216
    iget-boolean p0, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->closePending:Z

    .line 217
    .line 218
    if-nez p0, :cond_7

    .line 219
    .line 220
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnecting()Z

    .line 221
    .line 222
    .line 223
    move-result p0

    .line 224
    if-nez p0, :cond_6

    .line 225
    .line 226
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 227
    .line 228
    .line 229
    move-result p0

    .line 230
    if-eqz p0, :cond_5

    .line 231
    .line 232
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 233
    .line 234
    const/16 p1, 0x7d66

    .line 235
    .line 236
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 237
    .line 238
    .line 239
    throw p0

    .line 240
    :cond_5
    const/16 p0, 0x7d64

    .line 241
    .line 242
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    throw p0

    .line 247
    :cond_6
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 248
    .line 249
    const/16 p1, 0x7d6e

    .line 250
    .line 251
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 252
    .line 253
    .line 254
    throw p0

    .line 255
    :cond_7
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 256
    .line 257
    const/16 p1, 0x7d6f

    .line 258
    .line 259
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 260
    .line 261
    .line 262
    throw p0

    .line 263
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 264
    throw p0
.end method

.method public connectComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->getReturnCode()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    :try_start_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 11
    .line 12
    sget-object p2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 13
    .line 14
    const-string v1, "connectComplete"

    .line 15
    .line 16
    const-string v2, "215"

    .line 17
    .line 18
    invoke-interface {p1, p2, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    iput-byte p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 23
    .line 24
    monitor-exit v0

    .line 25
    return-void

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 30
    .line 31
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 32
    .line 33
    const-string v1, "connectComplete"

    .line 34
    .line 35
    const-string v2, "204"

    .line 36
    .line 37
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-interface {p0, v0, v1, v2, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    throw p2

    .line 49
    :goto_0
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 50
    throw p0
.end method

.method public deleteBufferedMessage(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->deleteMessage(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public deliveryComplete(I)V
    .locals 0

    .line 2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->deliveryComplete(I)V

    return-void
.end method

.method public deliveryComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->deliveryComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V

    return-void
.end method

.method public disconnect(Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;JLorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 9

    .line 1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isClosed()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_3

    .line 9
    .line 10
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnected()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_2

    .line 15
    .line 16
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 27
    .line 28
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->getThread()Ljava/lang/Thread;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    if-eq v0, v2, :cond_0

    .line 33
    .line 34
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 35
    .line 36
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 37
    .line 38
    const-string v3, "disconnect"

    .line 39
    .line 40
    const-string v4, "218"

    .line 41
    .line 42
    invoke-interface {v0, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const/4 v0, 0x2

    .line 46
    iput-byte v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 47
    .line 48
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;

    .line 49
    .line 50
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 51
    .line 52
    move-object v3, p0

    .line 53
    move-object v4, p1

    .line 54
    move-wide v5, p2

    .line 55
    move-object v7, p4

    .line 56
    invoke-direct/range {v2 .. v8}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;JLorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/util/concurrent/ExecutorService;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->start()V

    .line 60
    .line 61
    .line 62
    monitor-exit v1

    .line 63
    return-void

    .line 64
    :catchall_0
    move-exception v0

    .line 65
    move-object p0, v0

    .line 66
    goto :goto_0

    .line 67
    :cond_0
    move-object v3, p0

    .line 68
    iget-object p0, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 69
    .line 70
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 71
    .line 72
    const-string p2, "disconnect"

    .line 73
    .line 74
    const-string p3, "210"

    .line 75
    .line 76
    invoke-interface {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const/16 p0, 0x7d6b

    .line 80
    .line 81
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    throw p0

    .line 86
    :cond_1
    move-object v3, p0

    .line 87
    iget-object p0, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 88
    .line 89
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 90
    .line 91
    const-string p2, "disconnect"

    .line 92
    .line 93
    const-string p3, "219"

    .line 94
    .line 95
    invoke-interface {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    const/16 p0, 0x7d66

    .line 99
    .line 100
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    throw p0

    .line 105
    :cond_2
    move-object v3, p0

    .line 106
    iget-object p0, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 107
    .line 108
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 109
    .line 110
    const-string p2, "disconnect"

    .line 111
    .line 112
    const-string p3, "211"

    .line 113
    .line 114
    invoke-interface {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const/16 p0, 0x7d65

    .line 118
    .line 119
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    throw p0

    .line 124
    :cond_3
    move-object v3, p0

    .line 125
    iget-object p0, v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 126
    .line 127
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 128
    .line 129
    const-string p2, "disconnect"

    .line 130
    .line 131
    const-string p3, "223"

    .line 132
    .line 133
    invoke-interface {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const/16 p0, 0x7d6f

    .line 137
    .line 138
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    throw p0

    .line 143
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 144
    throw p0
.end method

.method public disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 8

    const/4 v5, 0x1

    move-object v0, p0

    move-wide v1, p1

    move-wide v3, p3

    move v6, p5

    move-object v7, p6

    .line 1
    invoke-virtual/range {v0 .. v7}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectForcibly(JJZILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    return-void
.end method

.method public disconnectForcibly(JJZILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/4 v0, 0x2

    .line 2
    iput-byte v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    if-eqz v0, :cond_0

    .line 4
    invoke-virtual {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesce(J)V

    .line 5
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    const/4 p2, 0x0

    if-eqz p5, :cond_1

    .line 6
    :try_start_0
    new-instance p5, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    invoke-direct {p5, p6, p7}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;-><init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    invoke-virtual {p0, p5, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 7
    invoke-virtual {p1, p3, p4}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->waitForCompletion(J)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p3

    .line 8
    iget-object p4, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {p4, p2, p2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 9
    invoke-virtual {p0, p1, p2, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 10
    throw p3

    .line 11
    :catch_0
    :cond_1
    :goto_0
    iget-object p3, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {p3, p2, p2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 12
    invoke-virtual {p0, p1, p2, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    return-void
.end method

.method public doesSubscriptionIdentifierExist(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->doesSubscriptionIdentifierExist(I)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getActualInFlight()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getActualInFlight()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getBufferedMessage(I)Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->getMessage(I)Lorg/eclipse/paho/mqttv5/client/BufferedMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->getMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 12
    .line 13
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public getBufferedMessageCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->getMessageCount()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 2
    .line 3
    return-object p0
.end method

.method public getClientState()Lorg/eclipse/paho/mqttv5/client/internal/MqttState;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 2
    .line 3
    return-object p0
.end method

.method public getConOptions()Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDebug()Ljava/util/Properties;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/Properties;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/Properties;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-byte v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 7
    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "conState"

    .line 13
    .line 14
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getServerURI()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    const-string v2, "serverURI"

    .line 26
    .line 27
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    const-string v1, "callback"

    .line 31
    .line 32
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 33
    .line 34
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->stoppingComms:Z

    .line 38
    .line 39
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    const-string v1, "stoppingComms"

    .line 44
    .line 45
    invoke-virtual {v0, v1, p0}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    return-object v0
.end method

.method public getKeepAlive()J
    .locals 2

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getKeepAlive()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public getNetworkModuleIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModuleIndex:I

    .line 2
    .line 3
    return p0
.end method

.method public getNetworkModules()[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModules:[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getOutstandingDelTokens()[Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getReceiver()Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->receiver:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTopic(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttTopic;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;

    .line 2
    .line 3
    invoke-direct {v0, p1, p0}, Lorg/eclipse/paho/mqttv5/client/MqttTopic;-><init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    filled-new-array {v2, p1, p2}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const-string v3, "internalSend"

    .line 14
    .line 15
    const-string v4, "200"

    .line 16
    .line 17
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    iget-object v0, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 27
    .line 28
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V

    .line 33
    .line 34
    .line 35
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 36
    .line 37
    invoke-virtual {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :catch_0
    move-exception v0

    .line 42
    iget-object p2, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    invoke-virtual {p2, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V

    .line 46
    .line 47
    .line 48
    instance-of p2, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 49
    .line 50
    if-eqz p2, :cond_0

    .line 51
    .line 52
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 53
    .line 54
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 55
    .line 56
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->undo(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V

    .line 57
    .line 58
    .line 59
    :cond_0
    throw v0

    .line 60
    :cond_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 61
    .line 62
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    filled-new-array {v0, p1, p2}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    const-string p2, "213"

    .line 71
    .line 72
    invoke-interface {p0, v1, v3, p2, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 76
    .line 77
    const/16 p1, 0x7dc9

    .line 78
    .line 79
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 80
    .line 81
    .line 82
    throw p0
.end method

.method public isClosed()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 5
    .line 6
    const/4 v1, 0x4

    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    :goto_0
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public isConnected()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    :goto_0
    monitor-exit v0

    .line 12
    return p0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method

.method public isConnecting()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v1, 0x0

    .line 11
    :goto_0
    monitor-exit v0

    .line 12
    return v1

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method

.method public isDisconnected()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 5
    .line 6
    const/4 v1, 0x3

    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    :goto_0
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public isDisconnecting()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    :goto_0
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public isResting()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->resting:Z

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public messageArrivedComplete(II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageArrivedComplete(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public notifyReconnect()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 6
    .line 7
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 8
    .line 9
    const-string v2, "509"

    .line 10
    .line 11
    const-string v3, "notifyReconnect"

    .line 12
    .line 13
    invoke-interface {v0, v1, v3, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 17
    .line 18
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;

    .line 19
    .line 20
    invoke-direct {v1, p0, v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->setPublishCallback(Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 27
    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    new-instance v0, Ljava/lang/Thread;

    .line 31
    .line 32
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 33
    .line 34
    invoke-direct {v0, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 42
    .line 43
    invoke-interface {v0, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 44
    .line 45
    .line 46
    :cond_1
    return-void
.end method

.method public removeMessageListener(Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->removeMessageListener(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public sendNoWait(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-string v1, "sendNoWait"

    .line 6
    .line 7
    if-nez v0, :cond_4

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 16
    .line 17
    if-nez v0, :cond_4

    .line 18
    .line 19
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isResting()Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_3

    .line 39
    .line 40
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 41
    .line 42
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 43
    .line 44
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    const-string v4, "508"

    .line 53
    .line 54
    invoke-interface {v0, v2, v1, v4, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 58
    .line 59
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->isPersistBuffer()Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_2

    .line 64
    .line 65
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 66
    .line 67
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 68
    .line 69
    .line 70
    :cond_2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 71
    .line 72
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->putMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 77
    .line 78
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 79
    .line 80
    const-string p2, "208"

    .line 81
    .line 82
    invoke-interface {p0, p1, v1, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const/16 p0, 0x7d68

    .line 86
    .line 87
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    throw p0

    .line 92
    :cond_4
    :goto_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 93
    .line 94
    if-eqz v0, :cond_7

    .line 95
    .line 96
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->getMessageCount()I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-eqz v0, :cond_7

    .line 101
    .line 102
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 103
    .line 104
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    const-string v4, "507"

    .line 115
    .line 116
    invoke-interface {v0, v2, v1, v4, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 120
    .line 121
    if-eqz v0, :cond_5

    .line 122
    .line 123
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    if-eqz v0, :cond_5

    .line 132
    .line 133
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    const/4 v1, 0x0

    .line 138
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setTopicAlias(Ljava/lang/Integer;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setProperties(Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 142
    .line 143
    .line 144
    :cond_5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 145
    .line 146
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->isPersistBuffer()Z

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    if-eqz v0, :cond_6

    .line 151
    .line 152
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 153
    .line 154
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 155
    .line 156
    .line 157
    :cond_6
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 158
    .line 159
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->putMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :cond_7
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 164
    .line 165
    if-eqz v0, :cond_9

    .line 166
    .line 167
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 168
    .line 169
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getMaximumQoS()Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    if-eqz v0, :cond_8

    .line 174
    .line 175
    move-object v0, p1

    .line 176
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 177
    .line 178
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 183
    .line 184
    .line 185
    move-result v1

    .line 186
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 187
    .line 188
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getMaximumQoS()Ljava/lang/Integer;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 193
    .line 194
    .line 195
    move-result v2

    .line 196
    if-le v1, v2, :cond_8

    .line 197
    .line 198
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 203
    .line 204
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getMaximumQoS()Ljava/lang/Integer;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 209
    .line 210
    .line 211
    move-result v2

    .line 212
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setQos(I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 216
    .line 217
    .line 218
    :cond_8
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 219
    .line 220
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isRetainAvailable()Ljava/lang/Boolean;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    if-eqz v0, :cond_9

    .line 225
    .line 226
    move-object v0, p1

    .line 227
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 228
    .line 229
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->isRetained()Z

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    if-eqz v1, :cond_9

    .line 238
    .line 239
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 240
    .line 241
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isRetainAvailable()Ljava/lang/Boolean;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 246
    .line 247
    .line 248
    move-result v1

    .line 249
    if-nez v1, :cond_9

    .line 250
    .line 251
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    const/4 v2, 0x0

    .line 256
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setRetained(Z)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 260
    .line 261
    .line 262
    :cond_9
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 263
    .line 264
    .line 265
    return-void
.end method

.method public setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setDisconnectedMessageBuffer(Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 2
    .line 3
    return-void
.end method

.method public setManualAcks(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->setManualAcks(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setMessageListener(Ljava/lang/Integer;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->setMessageListener(Ljava/lang/Integer;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setNetworkModuleIndex(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModuleIndex:I

    .line 2
    .line 3
    return-void
.end method

.method public setNetworkModules([Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModules:[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 2
    .line 3
    return-void
.end method

.method public setReconnectCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->setReconnectCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setRestingState(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->resting:Z

    .line 2
    .line 3
    return-void
.end method

.method public shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->stoppingComms:Z

    .line 5
    .line 6
    if-nez v1, :cond_d

    .line 7
    .line 8
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->closePending:Z

    .line 9
    .line 10
    if-nez v1, :cond_d

    .line 11
    .line 12
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isClosed()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto/16 :goto_3

    .line 19
    .line 20
    :cond_0
    const/4 v1, 0x1

    .line 21
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->stoppingComms:Z

    .line 22
    .line 23
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 24
    .line 25
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 26
    .line 27
    const-string v4, "shutdownConnection"

    .line 28
    .line 29
    const-string v5, "216"

    .line 30
    .line 31
    invoke-interface {v2, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    const/4 v3, 0x0

    .line 39
    if-nez v2, :cond_1

    .line 40
    .line 41
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-nez v2, :cond_1

    .line 46
    .line 47
    move v2, v3

    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    goto/16 :goto_4

    .line 51
    .line 52
    :cond_1
    move v2, v1

    .line 53
    :goto_0
    const/4 v4, 0x2

    .line 54
    iput-byte v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 55
    .line 56
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    if-eqz p1, :cond_2

    .line 58
    .line 59
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->isComplete()Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-nez v0, :cond_2

    .line 64
    .line 65
    iget-object v0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 66
    .line 67
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setException(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 68
    .line 69
    .line 70
    :cond_2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 71
    .line 72
    if-eqz v0, :cond_3

    .line 73
    .line 74
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->stop()V

    .line 75
    .line 76
    .line 77
    :cond_3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->receiver:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 78
    .line 79
    if-eqz v0, :cond_4

    .line 80
    .line 81
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->stop()V

    .line 82
    .line 83
    .line 84
    :cond_4
    :try_start_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModules:[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 85
    .line 86
    if-eqz v0, :cond_5

    .line 87
    .line 88
    iget v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->networkModuleIndex:I

    .line 89
    .line 90
    aget-object v0, v0, v4

    .line 91
    .line 92
    if-eqz v0, :cond_5

    .line 93
    .line 94
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;->stop()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 95
    .line 96
    .line 97
    :catch_0
    :cond_5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 98
    .line 99
    new-instance v4, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 100
    .line 101
    const/16 v5, 0x7d66

    .line 102
    .line 103
    invoke-direct {v4, v5}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->quiesce(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 107
    .line 108
    .line 109
    invoke-direct {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->handleOldTokens(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    :try_start_2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 114
    .line 115
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->disconnected(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 116
    .line 117
    .line 118
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 119
    .line 120
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getCleanStart()Z

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    if-eqz v0, :cond_6

    .line 125
    .line 126
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 127
    .line 128
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->removeMessageListeners()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 129
    .line 130
    .line 131
    :catch_1
    :cond_6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sender:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 132
    .line 133
    if-eqz v0, :cond_7

    .line 134
    .line 135
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->stop()V

    .line 136
    .line 137
    .line 138
    :cond_7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 139
    .line 140
    if-eqz v0, :cond_8

    .line 141
    .line 142
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/MqttPingSender;->stop()V

    .line 143
    .line 144
    .line 145
    :cond_8
    :try_start_3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectedMessageBuffer:Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 146
    .line 147
    if-nez v0, :cond_9

    .line 148
    .line 149
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 150
    .line 151
    if-eqz v0, :cond_9

    .line 152
    .line 153
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->close()V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_2

    .line 154
    .line 155
    .line 156
    :catch_2
    :cond_9
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 157
    .line 158
    monitor-enter v4

    .line 159
    :try_start_4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 160
    .line 161
    sget-object v5, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->CLASS_NAME:Ljava/lang/String;

    .line 162
    .line 163
    const-string v6, "shutdownConnection"

    .line 164
    .line 165
    const-string v7, "217"

    .line 166
    .line 167
    invoke-interface {v0, v5, v6, v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    const/4 v0, 0x3

    .line 171
    iput-byte v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conState:B

    .line 172
    .line 173
    iput-boolean v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->stoppingComms:Z

    .line 174
    .line 175
    monitor-exit v4
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 176
    if-eqz p1, :cond_a

    .line 177
    .line 178
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 179
    .line 180
    if-eqz v0, :cond_a

    .line 181
    .line 182
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->asyncOperationComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 183
    .line 184
    .line 185
    :cond_a
    if-eqz v2, :cond_b

    .line 186
    .line 187
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 188
    .line 189
    if-eqz p1, :cond_b

    .line 190
    .line 191
    invoke-virtual {p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->connectionLost(Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 192
    .line 193
    .line 194
    :cond_b
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->conLock:Ljava/lang/Object;

    .line 195
    .line 196
    monitor-enter p1

    .line 197
    :try_start_5
    iget-boolean p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->closePending:Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 198
    .line 199
    if-eqz p2, :cond_c

    .line 200
    .line 201
    :try_start_6
    invoke-virtual {p0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->close(Z)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_3
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 202
    .line 203
    .line 204
    goto :goto_1

    .line 205
    :catchall_1
    move-exception p0

    .line 206
    goto :goto_2

    .line 207
    :catch_3
    :cond_c
    :goto_1
    :try_start_7
    monitor-exit p1

    .line 208
    return-void

    .line 209
    :goto_2
    monitor-exit p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 210
    throw p0

    .line 211
    :catchall_2
    move-exception p0

    .line 212
    :try_start_8
    monitor-exit v4
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 213
    throw p0

    .line 214
    :cond_d
    :goto_3
    :try_start_9
    monitor-exit v0

    .line 215
    return-void

    .line 216
    :goto_4
    monitor-exit v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 217
    throw p0
.end method
