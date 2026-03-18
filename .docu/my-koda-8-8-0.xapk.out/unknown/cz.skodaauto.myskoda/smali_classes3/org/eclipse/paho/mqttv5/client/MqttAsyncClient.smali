.class public Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;
.implements Lorg/eclipse/paho/mqttv5/client/IMqttAsyncClient;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;,
        Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;,
        Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;
    }
.end annotation


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.MqttAsyncClient"

.field private static final DISCONNECT_TIMEOUT:J = 0x2710L

.field private static final MAX_HIGH_SURROGATE:C = '\udbff'

.field private static final MIN_HIGH_SURROGATE:C = '\ud800'

.field private static final QUIESCE_TIMEOUT:J = 0x7530L

.field private static final clientLock:Ljava/lang/Object;

.field private static reconnectDelay:I = 0x3e8


# instance fields
.field protected comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

.field private executorService:Ljava/util/concurrent/ScheduledExecutorService;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

.field private mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

.field private mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

.field private persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

.field private pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

.field private reconnectTimer:Ljava/util/Timer;

.field private reconnecting:Z

.field private serverURI:Ljava/lang/String;

.field private topics:Ljava/util/Hashtable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Hashtable<",
            "Ljava/lang/String;",
            "Lorg/eclipse/paho/mqttv5/client/MqttTopic;",
            ">;"
        }
    .end annotation
.end field

.field private userContext:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->clientLock:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;-><init>()V

    invoke-direct {p0, p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;-><init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;)V
    .locals 6

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    .line 2
    invoke-direct/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;-><init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Ljava/util/concurrent/ScheduledExecutorService;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Ljava/util/concurrent/ScheduledExecutorService;)V
    .locals 7

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string v1, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    invoke-static {v1, v0}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    move-result-object v1

    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    const/4 v1, 0x0

    .line 5
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnecting:Z

    .line 6
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    invoke-direct {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;-><init>()V

    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    invoke-interface {v1, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    if-eqz p2, :cond_1

    .line 8
    new-instance v1, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 9
    new-instance v2, Ljava/io/DataOutputStream;

    invoke-direct {v2, v1}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 10
    invoke-static {v2, p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 11
    invoke-virtual {v2}, Ljava/io/DataOutputStream;->size()I

    move-result v1

    add-int/lit8 v1, v1, -0x2

    const v2, 0xffff

    if-gt v1, v2, :cond_0

    goto :goto_0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "ClientId longer than 65535 characters"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 13
    :cond_1
    const-string p2, ""

    .line 14
    :goto_0
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-direct {v1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;-><init>(Ljava/lang/String;)V

    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 15
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModuleService;->validateURI(Ljava/lang/String;)V

    .line 16
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->serverURI:Ljava/lang/String;

    .line 17
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    invoke-virtual {v1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->setClientId(Ljava/lang/String;)V

    .line 18
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    if-nez p3, :cond_2

    .line 19
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;

    invoke-direct {v1}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;-><init>()V

    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 20
    :cond_2
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->executorService:Ljava/util/concurrent/ScheduledExecutorService;

    .line 21
    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    if-nez p4, :cond_3

    .line 22
    new-instance p4, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    invoke-direct {p4, p5}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;-><init>(Ljava/util/concurrent/ScheduledExecutorService;)V

    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 23
    :cond_3
    iget-object p4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    const-string p5, "101"

    filled-new-array {p2, p1, p3}, [Ljava/lang/Object;

    move-result-object p1

    const-string p3, "MqttAsyncClient"

    invoke-interface {p4, v0, p3, p5, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    invoke-interface {p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->open(Ljava/lang/String;)V

    .line 25
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->executorService:Ljava/util/concurrent/ScheduledExecutorService;

    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 26
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    move-object v1, p0

    invoke-direct/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Ljava/util/concurrent/ExecutorService;Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;)V

    .line 27
    iput-object v0, v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 28
    iget-object p0, v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->close()V

    .line 29
    new-instance p0, Ljava/util/Hashtable;

    invoke-direct {p0}, Ljava/util/Hashtable;-><init>()V

    iput-object p0, v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->topics:Ljava/util/Hashtable;

    return-void
.end method

.method public static Character_isHighSurrogate(C)Z
    .locals 1

    .line 1
    const v0, 0xd800

    .line 2
    .line 3
    .line 4
    if-lt p0, v0, :cond_0

    .line 5
    .line 6
    const v0, 0xdbff

    .line 7
    .line 8
    .line 9
    if-gt p0, v0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public static synthetic access$0(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$1()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$10()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->clientLock:Ljava/lang/Object;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$11(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Ljava/util/Timer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectTimer:Ljava/util/Timer;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$2(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->attemptReconnect()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$3(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnecting:Z

    .line 2
    .line 3
    return-void
.end method

.method public static synthetic access$4(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->startReconnectCycle()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$5(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->stopReconnectCycle()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$6()I
    .locals 1

    .line 1
    sget v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectDelay:I

    .line 2
    .line 3
    return v0
.end method

.method public static synthetic access$7(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$8(I)V
    .locals 0

    .line 1
    sput p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectDelay:I

    .line 2
    .line 3
    return-void
.end method

.method public static synthetic access$9(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 2
    .line 3
    return-object p0
.end method

.method private attemptReconnect()V
    .locals 7

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 6
    .line 7
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const-string v3, "attemptReconnect"

    .line 16
    .line 17
    const-string v4, "500"

    .line 18
    .line 19
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 23
    .line 24
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->userContext:Ljava/lang/Object;

    .line 25
    .line 26
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;

    .line 27
    .line 28
    invoke-direct {v2, p0, v3}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttSecurityException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :catch_0
    move-exception v0

    .line 36
    move-object v6, v0

    .line 37
    goto :goto_0

    .line 38
    :catch_1
    move-exception v0

    .line 39
    move-object v6, v0

    .line 40
    goto :goto_1

    .line 41
    :goto_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 42
    .line 43
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 44
    .line 45
    const-string v4, "804"

    .line 46
    .line 47
    const/4 v5, 0x0

    .line 48
    const-string v3, "attemptReconnect"

    .line 49
    .line 50
    invoke-interface/range {v1 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 51
    .line 52
    .line 53
    goto :goto_2

    .line 54
    :goto_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 55
    .line 56
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 57
    .line 58
    const-string v4, "804"

    .line 59
    .line 60
    const/4 v5, 0x0

    .line 61
    const-string v3, "attemptReconnect"

    .line 62
    .line 63
    invoke-interface/range {v1 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    :goto_2
    return-void
.end method

.method private createNetworkModule(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "115"

    .line 6
    .line 7
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    const-string v4, "createNetworkModule"

    .line 12
    .line 13
    invoke-interface {v0, v1, v4, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 17
    .line 18
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {p1, p2, p0}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModuleService;->createInstance(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method private getHostName(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const/16 p0, 0x3a

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/lang/String;->indexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/4 v0, -0x1

    .line 8
    if-ne p0, v0, :cond_0

    .line 9
    .line 10
    const/16 p0, 0x2f

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Ljava/lang/String;->indexOf(I)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    :cond_0
    if-ne p0, v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    :cond_1
    const/4 v0, 0x0

    .line 23
    invoke-virtual {p1, v0, p0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method private startReconnectCycle()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 6
    .line 7
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    sget v3, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectDelay:I

    .line 12
    .line 13
    int-to-long v3, v3

    .line 14
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    filled-new-array {v2, v3}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const-string v3, "startReconnectCycle"

    .line 23
    .line 24
    const-string v4, "503"

    .line 25
    .line 26
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Ljava/util/Timer;

    .line 30
    .line 31
    new-instance v1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v2, "MQTT Reconnect: "

    .line 34
    .line 35
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 39
    .line 40
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-direct {v0, v1}, Ljava/util/Timer;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectTimer:Ljava/util/Timer;

    .line 55
    .line 56
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;

    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    invoke-direct {v1, p0, v2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;)V

    .line 60
    .line 61
    .line 62
    sget p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectDelay:I

    .line 63
    .line 64
    int-to-long v2, p0

    .line 65
    invoke-virtual {v0, v1, v2, v3}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;J)V

    .line 66
    .line 67
    .line 68
    return-void
.end method

.method private stopReconnectCycle()V
    .locals 5

    .line 1
    const-string v0, "stopReconnectCycle"

    .line 2
    .line 3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    .line 5
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 6
    .line 7
    const-string v3, "504"

    .line 8
    .line 9
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 10
    .line 11
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-interface {v1, v2, v0, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->clientLock:Ljava/lang/Object;

    .line 23
    .line 24
    monitor-enter v0

    .line 25
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 26
    .line 27
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isAutomaticReconnect()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectTimer:Ljava/util/Timer;

    .line 34
    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/util/Timer;->cancel()V

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectTimer:Ljava/util/Timer;

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    :goto_0
    const/16 p0, 0x3e8

    .line 47
    .line 48
    sput p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnectDelay:I

    .line 49
    .line 50
    :cond_1
    monitor-exit v0

    .line 51
    return-void

    .line 52
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    throw p0
.end method

.method private subscribeBase([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-interface {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->isLoggable(I)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const-string v1, "subscribe"

    .line 9
    .line 10
    if-eqz v0, :cond_2

    .line 11
    .line 12
    new-instance v0, Ljava/lang/StringBuffer;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    .line 15
    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    :goto_0
    array-length v3, p1

    .line 19
    if-lt v2, v3, :cond_0

    .line 20
    .line 21
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 22
    .line 23
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    filled-new-array {v0, p2, p3}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const-string v4, "106"

    .line 34
    .line 35
    invoke-interface {v2, v3, v1, v4, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    if-lez v2, :cond_1

    .line 40
    .line 41
    const-string v3, ", "

    .line 42
    .line 43
    invoke-virtual {v0, v3}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 44
    .line 45
    .line 46
    :cond_1
    aget-object v3, p1, v2

    .line 47
    .line 48
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-virtual {v0, v3}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 53
    .line 54
    .line 55
    add-int/lit8 v2, v2, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    :goto_1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 59
    .line 60
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-direct {v0, v2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;

    .line 74
    .line 75
    invoke-direct {p2, p1, p4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;-><init>([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setRequestMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 79
    .line 80
    .line 81
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 82
    .line 83
    invoke-virtual {p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sendNoWait(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 87
    .line 88
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 89
    .line 90
    const-string p2, "109"

    .line 91
    .line 92
    invoke-interface {p0, p1, v1, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-object v0
.end method


# virtual methods
.method public authenticate(ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;

    .line 14
    .line 15
    invoke-direct {p2, p1, p3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;-><init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 19
    .line 20
    invoke-virtual {p0, p2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sendNoWait(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 21
    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    return-object p0
.end method

.method public checkPing(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 3

    .line 1
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v1, "117"

    .line 6
    .line 7
    const-string v2, "ping"

    .line 8
    .line 9
    invoke-interface {p1, v0, v2, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 13
    .line 14
    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->checkForActivity(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 19
    .line 20
    const-string p2, "118"

    .line 21
    .line 22
    invoke-interface {p0, v0, v2, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object p1
.end method

.method public close()V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->close(Z)V

    return-void
.end method

.method public close(Z)V
    .locals 4

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string v2, "113"

    const-string v3, "close"

    invoke-interface {v0, v1, v3, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->close(Z)V

    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    const-string p1, "114"

    invoke-interface {p0, v1, v3, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public connect()Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connect(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public connect(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;-><init>()V

    invoke-virtual {p0, v0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 3
    invoke-virtual {p0, p1, v0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 13

    .line 4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    move-result v0

    if-nez v0, :cond_8

    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnecting()Z

    move-result v0

    if-nez v0, :cond_7

    .line 6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    move-result v0

    if-nez v0, :cond_6

    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isClosed()Z

    move-result v0

    if-nez v0, :cond_5

    if-nez p1, :cond_0

    .line 8
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;-><init>()V

    :cond_0
    move-object v4, p1

    .line 9
    iput-object v4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 10
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->userContext:Ljava/lang/Object;

    .line 11
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isAutomaticReconnect()Z

    move-result p1

    .line 12
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 13
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getConnectionTimeout()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    .line 14
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getKeepAliveInterval()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getUserName()Ljava/lang/String;

    move-result-object v8

    .line 15
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getPassword()[B

    move-result-object v2

    const-string v3, "[notnull]"

    const-string v9, "[null]"

    if-nez v2, :cond_1

    move-object v2, v9

    goto :goto_0

    :cond_1
    move-object v2, v9

    move-object v9, v3

    .line 16
    :goto_0
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getWillMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    move-result-object v10

    if-nez v10, :cond_2

    move-object v10, v2

    :goto_1
    move-object v11, p2

    move-object/from16 v12, p3

    goto :goto_2

    :cond_2
    move-object v10, v3

    goto :goto_1

    :goto_2
    filled-new-array/range {v5 .. v12}, [Ljava/lang/Object;

    move-result-object v2

    .line 17
    const-string v3, "connect"

    const-string v5, "103"

    invoke-interface {v0, v1, v3, v5, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->serverURI:Ljava/lang/String;

    invoke-virtual {p0, v1, v4}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->createNetworkModules(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    move-result-object v1

    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setNetworkModules([Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;)V

    .line 19
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    new-instance v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;

    invoke-direct {v1, p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Z)V

    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setReconnectCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 20
    new-instance v5, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v5, p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 21
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;

    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 22
    iget-boolean v8, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnecting:Z

    iget-object v9, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    iget-object v10, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    move-object v1, p0

    move-object v6, p2

    move-object/from16 v7, p3

    .line 23
    invoke-direct/range {v0 .. v10}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Lorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ZLorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;)V

    .line 24
    invoke-virtual {v5, v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 25
    invoke-virtual {v5, p0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 26
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isSendReasonMessages()Z

    move-result p2

    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setSendReasonMessages(Z)V

    .line 27
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    if-eqz p1, :cond_3

    .line 28
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->setMqttCallbackExtended(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 29
    :cond_3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isCleanStart()Z

    move-result p1

    if-eqz p1, :cond_4

    .line 30
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->clearSessionState()V

    .line 31
    :cond_4
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->clearConnectionState()V

    .line 32
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getTopicAliasMaximum()Ljava/lang/Integer;

    move-result-object p2

    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->setIncomingTopicAliasMax(Ljava/lang/Integer;)V

    .line 33
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setNetworkModuleIndex(I)V

    .line 34
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ConnectActionListener;->connect()V

    return-object v5

    .line 35
    :cond_5
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    const/16 p1, 0x7d6f

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    throw p0

    .line 36
    :cond_6
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    const/16 p1, 0x7d66

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    throw p0

    .line 37
    :cond_7
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    const/16 p1, 0x7d6e

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    throw p0

    :cond_8
    const/16 p0, 0x7d64

    .line 38
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    move-result-object p0

    throw p0
.end method

.method public createNetworkModules(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "116"

    .line 6
    .line 7
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    const-string v4, "createNetworkModules"

    .line 12
    .line 13
    invoke-interface {v0, v1, v4, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getServerURIs()[Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v1, 0x0

    .line 21
    const/4 v2, 0x1

    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    new-array v0, v2, [Ljava/lang/String;

    .line 25
    .line 26
    aput-object p1, v0, v1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    array-length v3, v0

    .line 30
    if-nez v3, :cond_1

    .line 31
    .line 32
    new-array v0, v2, [Ljava/lang/String;

    .line 33
    .line 34
    aput-object p1, v0, v1

    .line 35
    .line 36
    :cond_1
    :goto_0
    array-length p1, v0

    .line 37
    new-array p1, p1, [Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 38
    .line 39
    :goto_1
    array-length v2, v0

    .line 40
    if-lt v1, v2, :cond_2

    .line 41
    .line 42
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 43
    .line 44
    sget-object p2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 45
    .line 46
    const-string v0, "108"

    .line 47
    .line 48
    invoke-interface {p0, p2, v4, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    return-object p1

    .line 52
    :cond_2
    aget-object v2, v0, v1

    .line 53
    .line 54
    invoke-direct {p0, v2, p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->createNetworkModule(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    aput-object v2, p1, v1

    .line 59
    .line 60
    add-int/lit8 v1, v1, 0x1

    .line 61
    .line 62
    goto :goto_1
.end method

.method public deleteBufferedMessage(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->deleteBufferedMessage(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public disconnect()Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 3
    invoke-virtual {p0, v0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnect(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public disconnect(J)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 7

    .line 4
    new-instance v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-wide v1, p1

    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnect(JLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public disconnect(JLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 6

    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    filled-new-array {v2, p3, p4}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "disconnect"

    const-string v4, "104"

    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 7
    invoke-virtual {v0, p4}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 8
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 9
    new-instance p3, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    invoke-direct {p3, p5, p6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;-><init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 10
    :try_start_0
    iget-object p4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {p4, p3, p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnect(Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;JLorg/eclipse/paho/mqttv5/client/MqttToken;)V

    const-wide/16 p1, 0x64

    .line 11
    invoke-static {p1, p2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    goto :goto_0

    :catch_0
    move-exception v0

    move-object p1, v0

    move-object v5, p1

    goto :goto_1

    .line 12
    :catch_1
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object p1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string p2, "108"

    invoke-interface {p0, p1, v3, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-object v0

    .line 13
    :goto_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string v3, "105"

    const/4 v4, 0x0

    const-string v2, "disconnect"

    invoke-interface/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 14
    throw v5
.end method

.method public disconnect(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 7

    .line 1
    new-instance v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const-wide/16 v1, 0x7530

    const/4 v5, 0x0

    move-object v0, p0

    move-object v3, p1

    move-object v4, p2

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnect(JLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public disconnectForcibly()V
    .locals 7

    .line 1
    new-instance v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const-wide/16 v1, 0x7530

    const-wide/16 v3, 0x2710

    const/4 v5, 0x0

    move-object v0, p0

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    return-void
.end method

.method public disconnectForcibly(J)V
    .locals 7

    .line 3
    new-instance v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const-wide/16 v1, 0x7530

    const/4 v5, 0x0

    move-object v0, p0

    move-wide v3, p1

    .line 4
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    return-void
.end method

.method public disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 7

    .line 5
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    move-wide v1, p1

    move-wide v3, p3

    move v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    const-wide/16 p1, 0x64

    .line 6
    invoke-static {p1, p2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    goto :goto_0

    :catch_0
    move-exception v0

    move-object p1, v0

    move-object v5, p1

    goto :goto_1

    .line 7
    :catch_1
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object p1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string p2, "disconnectForcibly"

    const-string p3, "108"

    invoke-interface {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void

    .line 8
    :goto_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string v3, "105"

    const/4 v4, 0x0

    const-string v2, "disconnectForcibly"

    invoke-interface/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 9
    throw v5
.end method

.method public disconnectForcibly(JJZ)V
    .locals 8

    .line 10
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 11
    new-instance v7, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v7}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v6, 0x0

    move-wide v1, p1

    move-wide v3, p3

    move v5, p5

    .line 12
    invoke-virtual/range {v0 .. v7}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->disconnectForcibly(JJZILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    return-void
.end method

.method public getBufferedMessage(I)Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getBufferedMessage(I)Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getBufferedMessageCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getBufferedMessageCount()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getClientId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getCurrentServerURI()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getNetworkModules()[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getNetworkModuleIndex()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    aget-object p0, v0, p0

    .line 14
    .line 15
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;->getServerURI()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public getDebug()Lorg/eclipse/paho/mqttv5/client/util/Debug;
    .locals 2

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/util/Debug;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 4
    .line 5
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 10
    .line 11
    invoke-direct {v0, v1, p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;-><init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getInFlightMessageCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getActualInFlight()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getServerURI()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->serverURI:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTopic(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttTopic;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    invoke-static {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->topics:Ljava/util/Hashtable;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;

    .line 17
    .line 18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 19
    .line 20
    invoke-direct {v0, p1, v1}, Lorg/eclipse/paho/mqttv5/client/MqttTopic;-><init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->topics:Ljava/util/Hashtable;

    .line 24
    .line 25
    invoke-virtual {p0, p1, v0}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    :cond_0
    return-object v0
.end method

.method public isConnected()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public messageArrivedComplete(II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->messageArrivedComplete(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, p1, p2, v0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 5

    .line 8
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string v2, "111"

    filled-new-array {p1, p3, p4}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "publish"

    invoke-interface {v0, v1, v4, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 v0, 0x0

    const/4 v2, 0x1

    .line 9
    invoke-static {p1, v0, v2}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    .line 10
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v0, v3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 11
    iget-object v3, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {v3, v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setDeliveryToken(Z)V

    .line 12
    invoke-virtual {v0, p4}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 13
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 14
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 15
    iget-object p3, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p4

    invoke-virtual {p3, p4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setTopics([Ljava/lang/String;)V

    .line 16
    new-instance p3, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    move-result-object p4

    invoke-direct {p3, p1, p2, p4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;-><init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 17
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setRequestMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 18
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {p1, p3, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sendNoWait(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 19
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    const-string p1, "112"

    invoke-interface {p0, v1, v4, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method public publish(Ljava/lang/String;[BIZ)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move v4, p4

    .line 6
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->publish(Ljava/lang/String;[BIZLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public publish(Ljava/lang/String;[BIZLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    invoke-direct {v0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;-><init>([B)V

    .line 2
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setProperties(Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 3
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setQos(I)V

    .line 4
    invoke-virtual {v0, p4}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setRetained(Z)V

    .line 5
    invoke-virtual {p0, p1, v0, p5, p6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public reconnect()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 6
    .line 7
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const-string v3, "reconnect"

    .line 16
    .line 17
    const-string v4, "500"

    .line 18
    .line 19
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 23
    .line 24
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_3

    .line 29
    .line 30
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 31
    .line 32
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnecting()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-nez v0, :cond_2

    .line 37
    .line 38
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 39
    .line 40
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_1

    .line 45
    .line 46
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 47
    .line 48
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isClosed()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_0

    .line 53
    .line 54
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->stopReconnectCycle()V

    .line 55
    .line 56
    .line 57
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->attemptReconnect()V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :cond_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 62
    .line 63
    const/16 v0, 0x7d6f

    .line 64
    .line 65
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 70
    .line 71
    const/16 v0, 0x7d66

    .line 72
    .line 73
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_2
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 78
    .line 79
    const/16 v0, 0x7d6e

    .line 80
    .line 81
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_3
    const/16 p0, 0x7d64

    .line 86
    .line 87
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    throw p0
.end method

.method public setBufferOpts(Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;-><init>(Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setDisconnectedMessageBuffer(Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setClientId(Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->setClientId(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setManualAcks(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setManualAcks(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public subscribe(Ljava/lang/String;I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    .line 8
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    invoke-direct {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;-><init>(Ljava/lang/String;I)V

    filled-new-array {v0}, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object p1

    .line 9
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v0, 0x0

    .line 10
    invoke-virtual {p0, p1, v0, v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe(Ljava/lang/String;ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    invoke-direct {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;-><init>(Ljava/lang/String;I)V

    filled-new-array {v0}, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object p1

    .line 2
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 3
    invoke-virtual {p0, p1, p3, p4, p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 12
    filled-new-array {p1}, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object p1

    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1, v1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 0

    .line 22
    filled-new-array {p1}, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object p1

    invoke-virtual/range {p0 .. p5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 6

    .line 23
    filled-new-array {p1}, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object v1

    .line 24
    new-instance v5, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v0, p0

    move-object v4, p2

    .line 25
    invoke-virtual/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe([Ljava/lang/String;[I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, p1, p2, v0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Ljava/lang/String;[ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe([Ljava/lang/String;[ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 5

    .line 4
    array-length v0, p1

    new-array v0, v0, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    const/4 v1, 0x0

    .line 5
    :goto_0
    array-length v2, p1

    if-lt v1, v2, :cond_0

    .line 6
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    invoke-virtual {p0, v0, p3, p4, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0

    .line 7
    :cond_0
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    aget-object v3, p1, v1

    aget v4, p2, v1

    invoke-direct {v2, v3, v4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;-><init>(Ljava/lang/String;I)V

    aput-object v2, v0, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 13
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1, v1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 8

    .line 39
    invoke-virtual {p5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getSubscriptionIdentifiers()Ljava/util/List;

    move-result-object v0

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v2

    .line 40
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connOpts:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->useSubscriptionIdentifiers()Z

    move-result v3

    if-eqz v3, :cond_2

    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isSubscriptionIdentifiersAvailable()Ljava/lang/Boolean;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-eqz v3, :cond_2

    if-eqz v2, :cond_1

    .line 41
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v3, v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->doesSubscriptionIdentifierExist(I)Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    .line 42
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 43
    new-instance p1, Ljava/lang/StringBuilder;

    const-string p2, "The Subscription Identifier "

    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, " already exists."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 45
    :cond_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttSession:Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getNextSubscriptionIdentifier()Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v2

    .line 46
    :cond_2
    :goto_0
    array-length v0, p1

    move v3, v1

    :goto_1
    if-lt v3, v0, :cond_4

    .line 47
    :try_start_0
    invoke-direct {p0, p1, p2, p3, p5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribeBase([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p2

    .line 48
    array-length p3, p1

    :goto_2
    if-ge v1, p3, :cond_3

    aget-object p4, p1, v1

    .line 49
    iget-object p5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {p4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object p4

    invoke-virtual {p5, p4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->removeMessageListener(Ljava/lang/String;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    .line 50
    :cond_3
    throw p2

    .line 51
    :cond_4
    aget-object v4, p1, v3

    .line 52
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v5

    .line 53
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v6}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isWildcardSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    .line 54
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v7}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isSharedSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    .line 55
    invoke-static {v5, v6, v7}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    if-nez p4, :cond_5

    .line 56
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v5, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->removeMessageListener(Ljava/lang/String;)V

    goto :goto_3

    .line 57
    :cond_5
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v5, v6, v4, p4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setMessageListener(Ljava/lang/Integer;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)V

    :goto_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_1
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 5

    .line 14
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-lt v1, v0, :cond_0

    .line 15
    invoke-direct {p0, p1, p2, p3, p4}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribeBase([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0

    .line 16
    :cond_0
    aget-object v2, p1, v1

    .line 17
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->removeMessageListener(Ljava/lang/String;)V

    .line 18
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v2

    .line 19
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isWildcardSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    .line 20
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isSharedSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    .line 21
    invoke-static {v2, v3, v4}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 6

    const/4 v0, 0x0

    move v1, v0

    .line 27
    :goto_0
    array-length v2, p1

    if-lt v1, v2, :cond_1

    .line 28
    :try_start_0
    invoke-direct {p0, p1, p2, p3, p5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribeBase([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p2

    .line 29
    array-length p3, p1

    :goto_1
    if-ge v0, p3, :cond_0

    aget-object p4, p1, v0

    .line 30
    iget-object p5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {p4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object p4

    invoke-virtual {p5, p4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->removeMessageListener(Ljava/lang/String;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 31
    :cond_0
    throw p2

    .line 32
    :cond_1
    aget-object v2, p1, v1

    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v2

    .line 33
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isWildcardSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    .line 34
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isSharedSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    .line 35
    invoke-static {v2, v3, v4}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    if-eqz p4, :cond_3

    .line 36
    aget-object v2, p4, v1

    if-nez v2, :cond_2

    goto :goto_2

    .line 37
    :cond_2
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    aget-object v3, p1, v1

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v3

    aget-object v4, p4, v1

    const/4 v5, 0x0

    invoke-virtual {v2, v5, v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setMessageListener(Ljava/lang/Integer;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)V

    goto :goto_3

    .line 38
    :cond_3
    :goto_2
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    aget-object v3, p1, v1

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->removeMessageListener(Ljava/lang/String;)V

    :goto_3
    add-int/lit8 v1, v1, 0x1

    goto :goto_0
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 6

    .line 26
    new-instance v5, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v4, p2

    invoke-virtual/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public unsubscribe(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 2
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1, v1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->unsubscribe([Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public unsubscribe(Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    .line 1
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    invoke-virtual {p0, p1, p2, p3, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->unsubscribe([Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public unsubscribe([Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 3
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1, v1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->unsubscribe([Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public unsubscribe([Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 7

    .line 4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    const/4 v1, 0x5

    invoke-interface {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->isLoggable(I)Z

    move-result v0

    const-string v1, "unsubscribe"

    const/4 v2, 0x0

    if-eqz v0, :cond_2

    .line 5
    const-string v0, ""

    move v3, v2

    :goto_0
    array-length v4, p1

    if-lt v3, v4, :cond_0

    .line 6
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v4, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string v5, "107"

    filled-new-array {v0, p2, p3}, [Ljava/lang/Object;

    move-result-object v0

    invoke-interface {v3, v4, v1, v5, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    if-lez v3, :cond_1

    .line 7
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const-string v4, ", "

    invoke-virtual {v0, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 8
    :cond_1
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    aget-object v0, p1, v3

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    .line 9
    :cond_2
    :goto_1
    array-length v0, p1

    move v3, v2

    :goto_2
    if-lt v3, v0, :cond_4

    .line 10
    array-length v4, p1

    :goto_3
    if-lt v2, v4, :cond_3

    .line 11
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 12
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 13
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setUserContext(Ljava/lang/Object;)V

    .line 14
    iget-object p2, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {p2, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setTopics([Ljava/lang/String;)V

    .line 15
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;

    invoke-direct {p2, p1, p4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;-><init>([Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 16
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setRequestMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 17
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sendNoWait(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object p1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->CLASS_NAME:Ljava/lang/String;

    const-string p2, "110"

    invoke-interface {p0, p1, v1, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-object v0

    .line 19
    :cond_3
    aget-object v0, p1, v2

    .line 20
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v3, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->removeMessageListener(Ljava/lang/String;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_3

    .line 21
    :cond_4
    aget-object v4, p1, v3

    .line 22
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isSharedSubscriptionsAvailable()Ljava/lang/Boolean;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    const/4 v6, 0x1

    invoke-static {v4, v6, v5}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_2
.end method
