.class public Lorg/eclipse/paho/mqttv5/client/internal/ClientState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/internal/MqttState;


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.ClientState"

.field private static final MAX_MSG_ID:I = 0xffff

.field private static final MIN_MSG_ID:I = 0x1

.field private static final PERSISTENCE_CONFIRMED_PREFIX:Ljava/lang/String; = "sc-"

.field private static final PERSISTENCE_RECEIVED_PREFIX:Ljava/lang/String; = "r-"

.field private static final PERSISTENCE_SENT_BUFFERED_PREFIX:Ljava/lang/String; = "sb-"

.field private static final PERSISTENCE_SENT_PREFIX:Ljava/lang/String; = "s-"


# instance fields
.field private actualInFlight:I

.field private callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

.field private cleanStart:Z

.field private clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private connected:Z

.field private inFlightPubRels:I

.field private inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/Integer;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/Integer;",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation
.end field

.field private incomingTopicAliases:Ljava/util/Hashtable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Hashtable<",
            "Ljava/lang/Integer;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private lastInboundActivity:J

.field private lastOutboundActivity:J

.field private lastPing:J

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

.field private nextMsgId:I

.field private outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/Integer;",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation
.end field

.field private outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/Integer;",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation
.end field

.field private outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/Integer;",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation
.end field

.field private outgoingTopicAliases:Ljava/util/Hashtable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Hashtable<",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private volatile pendingFlows:Ljava/util/Vector;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation
.end field

.field private volatile pendingMessages:Ljava/util/Vector;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation
.end field

.field private persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

.field private pingCommand:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

.field private pingOutstanding:I

.field private final pingOutstandingLock:Ljava/lang/Object;

.field private pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

.field private final queueLock:Ljava/lang/Object;

.field private final quiesceLock:Ljava/lang/Object;

.field private quiescing:Z

.field private tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 5
    .line 6
    const-string v1, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 7
    .line 8
    invoke-static {v1, v0}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 19
    .line 20
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 21
    .line 22
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 23
    .line 24
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 25
    .line 26
    new-instance v4, Ljava/lang/Object;

    .line 27
    .line 28
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 32
    .line 33
    new-instance v4, Ljava/lang/Object;

    .line 34
    .line 35
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 36
    .line 37
    .line 38
    iput-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesceLock:Ljava/lang/Object;

    .line 39
    .line 40
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 41
    .line 42
    const-wide/16 v4, 0x0

    .line 43
    .line 44
    iput-wide v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 45
    .line 46
    iput-wide v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 47
    .line 48
    iput-wide v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastPing:J

    .line 49
    .line 50
    new-instance v4, Ljava/lang/Object;

    .line 51
    .line 52
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstandingLock:Ljava/lang/Object;

    .line 56
    .line 57
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 58
    .line 59
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->connected:Z

    .line 60
    .line 61
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 62
    .line 63
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 64
    .line 65
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 66
    .line 67
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 68
    .line 69
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 70
    .line 71
    invoke-virtual {p4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    invoke-interface {v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    invoke-interface {v1, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 83
    .line 84
    const-string v3, "<Init>"

    .line 85
    .line 86
    const-string v4, ""

    .line 87
    .line 88
    invoke-interface {v1, v0, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->finer(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 92
    .line 93
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 94
    .line 95
    .line 96
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 97
    .line 98
    new-instance v0, Ljava/util/Vector;

    .line 99
    .line 100
    invoke-direct {v0}, Ljava/util/Vector;-><init>()V

    .line 101
    .line 102
    .line 103
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 104
    .line 105
    new-instance v0, Ljava/util/Vector;

    .line 106
    .line 107
    invoke-virtual {p6}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getReceiveMaximum()Ljava/lang/Integer;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    invoke-direct {v0, v1}, Ljava/util/Vector;-><init>(I)V

    .line 116
    .line 117
    .line 118
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 119
    .line 120
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 121
    .line 122
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 123
    .line 124
    .line 125
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 126
    .line 127
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 128
    .line 129
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 130
    .line 131
    .line 132
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 133
    .line 134
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 135
    .line 136
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 137
    .line 138
    .line 139
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 140
    .line 141
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 142
    .line 143
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 144
    .line 145
    .line 146
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 147
    .line 148
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingReq;

    .line 149
    .line 150
    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingReq;-><init>()V

    .line 151
    .line 152
    .line 153
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingCommand:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 154
    .line 155
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 156
    .line 157
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 158
    .line 159
    new-instance v0, Ljava/util/Hashtable;

    .line 160
    .line 161
    invoke-direct {v0}, Ljava/util/Hashtable;-><init>()V

    .line 162
    .line 163
    .line 164
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outgoingTopicAliases:Ljava/util/Hashtable;

    .line 165
    .line 166
    new-instance v0, Ljava/util/Hashtable;

    .line 167
    .line 168
    invoke-direct {v0}, Ljava/util/Hashtable;-><init>()V

    .line 169
    .line 170
    .line 171
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->incomingTopicAliases:Ljava/util/Hashtable;

    .line 172
    .line 173
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 174
    .line 175
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 176
    .line 177
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 178
    .line 179
    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 180
    .line 181
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 182
    .line 183
    iput-object p6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 184
    .line 185
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->restoreState()V

    .line 186
    .line 187
    .line 188
    return-void
.end method

.method private decrementInFlight()V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 5
    .line 6
    add-int/lit8 v1, v1, -0x1

    .line 7
    .line 8
    iput v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 9
    .line 10
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 11
    .line 12
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 13
    .line 14
    const-string v4, "decrementInFlight"

    .line 15
    .line 16
    const-string v5, "646"

    .line 17
    .line 18
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-interface {v2, v3, v4, v5, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-nez v1, :cond_0

    .line 34
    .line 35
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    :goto_0
    monitor-exit v0

    .line 44
    return-void

    .line 45
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    throw p0
.end method

.method private declared-synchronized getNextMessageId()I
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    :cond_0
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    add-int/2addr v2, v3

    .line 9
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 10
    .line 11
    const v4, 0xffff

    .line 12
    .line 13
    .line 14
    if-le v2, v4, :cond_1

    .line 15
    .line 16
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catchall_0
    move-exception v0

    .line 20
    goto :goto_2

    .line 21
    :cond_1
    :goto_0
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 22
    .line 23
    if-ne v2, v0, :cond_3

    .line 24
    .line 25
    add-int/lit8 v1, v1, 0x1

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    if-eq v1, v3, :cond_2

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_2
    const/16 v0, 0x7d01

    .line 32
    .line 33
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    throw v0

    .line 38
    :cond_3
    :goto_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 39
    .line 40
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-virtual {v3, v2}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-nez v2, :cond_0

    .line 49
    .line 50
    iget v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 51
    .line 52
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 57
    .line 58
    invoke-virtual {v1, v0, v0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    iget v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    .line 63
    monitor-exit p0

    .line 64
    return v0

    .line 65
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 66
    throw v0
.end method

.method private getReceivedPersistenceKey(I)Ljava/lang/String;
    .locals 0

    .line 2
    const-string p0, "r-"

    .line 3
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private getReceivedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    const-string v0, "r-"

    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    move-result p1

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private getSendBufferedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v0, "sb-"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private getSendConfirmPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v0, "sc-"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v0, "s-"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private insertInOrder(Ljava/util/Vector;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    :goto_0
    invoke-virtual {p1}, Ljava/util/Vector;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-lt v0, v1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1, p2}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    invoke-virtual {p1, v0}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 21
    .line 22
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-le v1, p0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p1, p2, v0}, Ljava/util/Vector;->insertElementAt(Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 33
    .line 34
    goto :goto_0
.end method

.method private reOrder(Ljava/util/Vector;)Ljava/util/Vector;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;)",
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/util/Vector;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/Vector;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/util/Vector;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    goto :goto_4

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    move v1, v0

    .line 15
    move v2, v1

    .line 16
    move v3, v2

    .line 17
    move v4, v3

    .line 18
    :goto_0
    invoke-virtual {p1}, Ljava/util/Vector;->size()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    if-lt v1, v5, :cond_4

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 29
    .line 30
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    const v5, 0xffff

    .line 35
    .line 36
    .line 37
    sub-int/2addr v5, v2

    .line 38
    add-int/2addr v5, v1

    .line 39
    if-le v5, v3, :cond_1

    .line 40
    .line 41
    move v5, v0

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v5, v4

    .line 44
    :goto_1
    move v1, v5

    .line 45
    :goto_2
    invoke-virtual {p1}, Ljava/util/Vector;->size()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-lt v1, v2, :cond_3

    .line 50
    .line 51
    :goto_3
    if-lt v0, v5, :cond_2

    .line 52
    .line 53
    :goto_4
    return-object p0

    .line 54
    :cond_2
    invoke-virtual {p1, v0}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 59
    .line 60
    invoke-virtual {p0, v1}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    add-int/lit8 v0, v0, 0x1

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    invoke-virtual {p1, v1}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    check-cast v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 71
    .line 72
    invoke-virtual {p0, v2}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    add-int/lit8 v1, v1, 0x1

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_4
    invoke-virtual {p1, v1}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    check-cast v5, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 83
    .line 84
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    sub-int v2, v5, v2

    .line 89
    .line 90
    if-le v2, v3, :cond_5

    .line 91
    .line 92
    move v4, v1

    .line 93
    move v3, v2

    .line 94
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 95
    .line 96
    move v2, v5

    .line 97
    goto :goto_0
.end method

.method private declared-synchronized releaseMessageId(I)V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 3
    .line 4
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    monitor-exit p0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p1

    .line 14
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 15
    throw p1
.end method

.method private restoreInflightMessages()V
    .locals 8

    .line 1
    new-instance v0, Ljava/util/Vector;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 4
    .line 5
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getReceiveMaximum()Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-direct {v0, v1}, Ljava/util/Vector;-><init>(I)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 17
    .line 18
    new-instance v0, Ljava/util/Vector;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/Vector;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 24
    .line 25
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->keys()Ljava/util/Enumeration;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    const/4 v2, 0x1

    .line 36
    const-string v3, "restoreInflightMessages"

    .line 37
    .line 38
    if-nez v1, :cond_3

    .line 39
    .line 40
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->keys()Ljava/util/Enumeration;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    :goto_1
    invoke-interface {v1}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-nez v0, :cond_2

    .line 51
    .line 52
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->keys()Ljava/util/Enumeration;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :goto_2
    invoke-interface {v0}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-nez v1, :cond_1

    .line 63
    .line 64
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 65
    .line 66
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->reOrder(Ljava/util/Vector;)Ljava/util/Vector;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 71
    .line 72
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 73
    .line 74
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->reOrder(Ljava/util/Vector;)Ljava/util/Vector;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 79
    .line 80
    return-void

    .line 81
    :cond_1
    invoke-interface {v0}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 86
    .line 87
    invoke-virtual {v2, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    check-cast v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 92
    .line 93
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 94
    .line 95
    sget-object v5, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 96
    .line 97
    const-string v6, "512"

    .line 98
    .line 99
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    invoke-interface {v4, v5, v3, v6, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 107
    .line 108
    invoke-direct {p0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->insertInOrder(Ljava/util/Vector;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 109
    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_2
    invoke-interface {v1}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 117
    .line 118
    invoke-virtual {v4, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 123
    .line 124
    invoke-virtual {v4, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setDuplicate(Z)V

    .line 125
    .line 126
    .line 127
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 128
    .line 129
    sget-object v6, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 130
    .line 131
    const-string v7, "612"

    .line 132
    .line 133
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    invoke-interface {v5, v6, v3, v7, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 141
    .line 142
    invoke-direct {p0, v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->insertInOrder(Ljava/util/Vector;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_3
    invoke-interface {v0}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    check-cast v1, Ljava/lang/Integer;

    .line 151
    .line 152
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 153
    .line 154
    invoke-virtual {v4, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 159
    .line 160
    instance-of v5, v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 161
    .line 162
    if-eqz v5, :cond_4

    .line 163
    .line 164
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 165
    .line 166
    sget-object v6, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 167
    .line 168
    const-string v7, "610"

    .line 169
    .line 170
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-interface {v5, v6, v3, v7, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v4, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setDuplicate(Z)V

    .line 178
    .line 179
    .line 180
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 181
    .line 182
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 183
    .line 184
    invoke-direct {p0, v1, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->insertInOrder(Ljava/util/Vector;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 185
    .line 186
    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :cond_4
    instance-of v2, v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 190
    .line 191
    if-eqz v2, :cond_0

    .line 192
    .line 193
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 194
    .line 195
    sget-object v5, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 196
    .line 197
    const-string v6, "611"

    .line 198
    .line 199
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    invoke-interface {v2, v5, v3, v6, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 207
    .line 208
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 209
    .line 210
    invoke-direct {p0, v1, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->insertInOrder(Ljava/util/Vector;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 211
    .line 212
    .line 213
    goto/16 :goto_0
.end method

.method private restoreMessage(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 6

    .line 1
    :try_start_0
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->createWireMessage(Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    .line 4
    move-result-object p2
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    goto :goto_0

    .line 6
    :catch_0
    move-exception v0

    .line 7
    move-object v5, v0

    .line 8
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 11
    .line 12
    const-string v3, "602"

    .line 13
    .line 14
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    const-string v2, "restoreMessage"

    .line 19
    .line 20
    invoke-interface/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getCause()Ljava/lang/Throwable;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    instance-of p2, p2, Ljava/io/EOFException;

    .line 28
    .line 29
    if-eqz p2, :cond_1

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 34
    .line 35
    invoke-interface {p2, p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    const/4 p2, 0x0

    .line 39
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 40
    .line 41
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 42
    .line 43
    const-string v1, "601"

    .line 44
    .line 45
    filled-new-array {p1, p2}, [Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    const-string v2, "restoreMessage"

    .line 50
    .line 51
    invoke-interface {p0, v0, v2, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-object p2

    .line 55
    :cond_1
    throw v5
.end method


# virtual methods
.method public checkForActivity(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 14

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "checkForActivity"

    .line 6
    .line 7
    const-string v3, "616"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    new-array v5, v4, [Ljava/lang/Object;

    .line 11
    .line 12
    invoke-interface {v0, v1, v2, v3, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesceLock:Ljava/lang/Object;

    .line 16
    .line 17
    monitor-enter v0

    .line 18
    :try_start_0
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    monitor-exit v0

    .line 24
    return-object v3

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto/16 :goto_4

    .line 27
    .line 28
    :cond_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 30
    .line 31
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 32
    .line 33
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getKeepAlive()J

    .line 34
    .line 35
    .line 36
    move-result-wide v5

    .line 37
    invoke-virtual {v0, v5, v6}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 38
    .line 39
    .line 40
    move-result-wide v5

    .line 41
    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->connected:Z

    .line 42
    .line 43
    if-eqz v0, :cond_9

    .line 44
    .line 45
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 46
    .line 47
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getKeepAlive()J

    .line 48
    .line 49
    .line 50
    move-result-wide v7

    .line 51
    const-wide/16 v9, 0x0

    .line 52
    .line 53
    cmp-long v0, v7, v9

    .line 54
    .line 55
    if-lez v0, :cond_9

    .line 56
    .line 57
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 58
    .line 59
    .line 60
    move-result-wide v7

    .line 61
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstandingLock:Ljava/lang/Object;

    .line 62
    .line 63
    monitor-enter v0

    .line 64
    :try_start_1
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 65
    .line 66
    const v9, 0x186a0

    .line 67
    .line 68
    .line 69
    if-lez v2, :cond_2

    .line 70
    .line 71
    iget-wide v10, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 72
    .line 73
    sub-long v10, v7, v10

    .line 74
    .line 75
    int-to-long v12, v9

    .line 76
    add-long/2addr v12, v5

    .line 77
    cmp-long v10, v10, v12

    .line 78
    .line 79
    if-gez v10, :cond_1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 83
    .line 84
    const-string v2, "checkForActivity"

    .line 85
    .line 86
    const-string v3, "619"

    .line 87
    .line 88
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    iget-wide v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 93
    .line 94
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    iget-wide v9, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 99
    .line 100
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    iget-wide v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastPing:J

    .line 109
    .line 110
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    filled-new-array {v4, v5, v6, v7, p0}, [Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-interface {p1, v1, v2, v3, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    const/16 p0, 0x7d00

    .line 122
    .line 123
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    throw p0

    .line 128
    :catchall_1
    move-exception p0

    .line 129
    goto/16 :goto_3

    .line 130
    .line 131
    :cond_2
    :goto_0
    if-nez v2, :cond_4

    .line 132
    .line 133
    iget-wide v10, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 134
    .line 135
    sub-long v10, v7, v10

    .line 136
    .line 137
    const-wide/16 v12, 0x2

    .line 138
    .line 139
    mul-long/2addr v12, v5

    .line 140
    cmp-long v10, v10, v12

    .line 141
    .line 142
    if-gez v10, :cond_3

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 146
    .line 147
    const-string v2, "checkForActivity"

    .line 148
    .line 149
    const-string v3, "642"

    .line 150
    .line 151
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    iget-wide v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 156
    .line 157
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 158
    .line 159
    .line 160
    move-result-object v5

    .line 161
    iget-wide v9, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 162
    .line 163
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 164
    .line 165
    .line 166
    move-result-object v6

    .line 167
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    iget-wide v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastPing:J

    .line 172
    .line 173
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    filled-new-array {v4, v5, v6, v7, p0}, [Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    invoke-interface {p1, v1, v2, v3, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    const/16 p0, 0x7d02

    .line 185
    .line 186
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    throw p0

    .line 191
    :cond_4
    :goto_1
    if-nez v2, :cond_5

    .line 192
    .line 193
    iget-wide v10, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 194
    .line 195
    sub-long v10, v7, v10

    .line 196
    .line 197
    int-to-long v12, v9

    .line 198
    sub-long v12, v5, v12

    .line 199
    .line 200
    cmp-long v2, v10, v12

    .line 201
    .line 202
    if-gez v2, :cond_6

    .line 203
    .line 204
    :cond_5
    iget-wide v10, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 205
    .line 206
    sub-long v10, v7, v10

    .line 207
    .line 208
    int-to-long v12, v9

    .line 209
    sub-long v12, v5, v12

    .line 210
    .line 211
    cmp-long v2, v10, v12

    .line 212
    .line 213
    if-ltz v2, :cond_8

    .line 214
    .line 215
    :cond_6
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 216
    .line 217
    const-string v3, "checkForActivity"

    .line 218
    .line 219
    const-string v7, "620"

    .line 220
    .line 221
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 222
    .line 223
    .line 224
    move-result-object v8

    .line 225
    iget-wide v9, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 226
    .line 227
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    iget-wide v10, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 232
    .line 233
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 234
    .line 235
    .line 236
    move-result-object v10

    .line 237
    filled-new-array {v8, v9, v10}, [Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    invoke-interface {v2, v1, v3, v7, v8}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    new-instance v3, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 245
    .line 246
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 247
    .line 248
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    invoke-interface {v2}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    invoke-direct {v3, v2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    if-eqz p1, :cond_7

    .line 260
    .line 261
    invoke-virtual {v3, p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 262
    .line 263
    .line 264
    :cond_7
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 265
    .line 266
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingCommand:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 267
    .line 268
    invoke-virtual {p1, v3, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 269
    .line 270
    .line 271
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 272
    .line 273
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingCommand:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 274
    .line 275
    invoke-virtual {p1, v2, v4}, Ljava/util/Vector;->insertElementAt(Ljava/lang/Object;I)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyQueueLock()V

    .line 279
    .line 280
    .line 281
    goto :goto_2

    .line 282
    :cond_8
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 283
    .line 284
    const-string v2, "checkForActivity"

    .line 285
    .line 286
    const-string v4, "634"

    .line 287
    .line 288
    invoke-interface {p1, v1, v2, v4, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    iget-wide v9, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 292
    .line 293
    sub-long/2addr v7, v9

    .line 294
    sub-long/2addr v5, v7

    .line 295
    const-wide/16 v7, 0x1

    .line 296
    .line 297
    invoke-static {v7, v8, v5, v6}, Ljava/lang/Math;->max(JJ)J

    .line 298
    .line 299
    .line 300
    move-result-wide v5

    .line 301
    :goto_2
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 302
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 303
    .line 304
    const-string v0, "checkForActivity"

    .line 305
    .line 306
    const-string v2, "624"

    .line 307
    .line 308
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 309
    .line 310
    .line 311
    move-result-object v4

    .line 312
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v4

    .line 316
    invoke-interface {p1, v1, v0, v2, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 317
    .line 318
    .line 319
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 320
    .line 321
    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 322
    .line 323
    invoke-virtual {p1, v5, v6}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 324
    .line 325
    .line 326
    move-result-wide v0

    .line 327
    invoke-interface {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttPingSender;->schedule(J)V

    .line 328
    .line 329
    .line 330
    return-object v3

    .line 331
    :goto_3
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 332
    throw p0

    .line 333
    :cond_9
    return-object v3

    .line 334
    :goto_4
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 335
    throw p0
.end method

.method public checkQuiesceLock()Z
    .locals 12

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->count()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/util/Vector;->size()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 22
    .line 23
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiesced()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 30
    .line 31
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 32
    .line 33
    const-string v3, "checkQuiesceLock"

    .line 34
    .line 35
    const-string v4, "626"

    .line 36
    .line 37
    iget-boolean v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    iget v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 44
    .line 45
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 46
    .line 47
    .line 48
    move-result-object v7

    .line 49
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 50
    .line 51
    invoke-virtual {v5}, Ljava/util/Vector;->size()I

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    iget v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 60
    .line 61
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 66
    .line 67
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiesced()Z

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 72
    .line 73
    .line 74
    move-result-object v10

    .line 75
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 76
    .line 77
    .line 78
    move-result-object v11

    .line 79
    filled-new-array/range {v6 .. v11}, [Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-interface {v1, v2, v3, v4, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesceLock:Ljava/lang/Object;

    .line 87
    .line 88
    monitor-enter v1

    .line 89
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesceLock:Ljava/lang/Object;

    .line 90
    .line 91
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 92
    .line 93
    .line 94
    monitor-exit v1

    .line 95
    const/4 p0, 0x1

    .line 96
    return p0

    .line 97
    :catchall_0
    move-exception v0

    .line 98
    move-object p0, v0

    .line 99
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 100
    throw p0

    .line 101
    :cond_0
    const/4 p0, 0x0

    .line 102
    return p0
.end method

.method public clearConnectionState()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "clearConnectionState"

    .line 6
    .line 7
    const-string v3, "665"

    .line 8
    .line 9
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outgoingTopicAliases:Ljava/util/Hashtable;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/Hashtable;->clear()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->incomingTopicAliases:Ljava/util/Hashtable;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/util/Hashtable;->clear()V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public clearState()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "clearState"

    .line 6
    .line 7
    const-string v3, ">"

    .line 8
    .line 9
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 13
    .line 14
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->clear()V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/util/Vector;->clear()V

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/util/Vector;->clear()V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 50
    .line 51
    .line 52
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 53
    .line 54
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->clear()V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outgoingTopicAliases:Ljava/util/Hashtable;

    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/util/Hashtable;->clear()V

    .line 60
    .line 61
    .line 62
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->incomingTopicAliases:Ljava/util/Hashtable;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/util/Hashtable;->clear()V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public close()V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/Vector;->clear()V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/util/Vector;->clear()V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 38
    .line 39
    .line 40
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 41
    .line 42
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->clear()V

    .line 43
    .line 44
    .line 45
    const/4 v0, 0x0

    .line 46
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 47
    .line 48
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 49
    .line 50
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 51
    .line 52
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 53
    .line 54
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 55
    .line 56
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 57
    .line 58
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 59
    .line 60
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 61
    .line 62
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 63
    .line 64
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 65
    .line 66
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 67
    .line 68
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingCommand:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 69
    .line 70
    return-void
.end method

.method public connected()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "connected"

    .line 6
    .line 7
    const-string v3, "631"

    .line 8
    .line 9
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->connected:Z

    .line 14
    .line 15
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingSender:Lorg/eclipse/paho/mqttv5/client/MqttPingSender;

    .line 16
    .line 17
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/MqttPingSender;->start()V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public deliveryComplete(I)V
    .locals 5

    .line 4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "deliveryComplete"

    const-string v4, "641"

    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getReceivedPersistenceKey(I)Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 6
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public deliveryComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "deliveryComplete"

    const-string v4, "641"

    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getReceivedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public disconnected(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "disconnected"

    .line 6
    .line 7
    const-string v3, "633"

    .line 8
    .line 9
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, v1, v2, v3, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    const/4 p1, 0x0

    .line 17
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->connected:Z

    .line 18
    .line 19
    :try_start_0
    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->cleanStart:Z

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clearState()V

    .line 24
    .line 25
    .line 26
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clearConnectionState()V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/Vector;->clear()V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/util/Vector;->clear()V

    .line 37
    .line 38
    .line 39
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstandingLock:Ljava/lang/Object;

    .line 40
    .line 41
    monitor-enter v0
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    :try_start_1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 43
    .line 44
    monitor-exit v0

    .line 45
    return-void

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    :try_start_2
    throw p0
    :try_end_2
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_2 .. :try_end_2} :catch_0

    .line 49
    :catch_0
    return-void
.end method

.method public get()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 8

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x0

    .line 5
    move-object v2, v1

    .line 6
    :cond_0
    :goto_0
    if-eqz v2, :cond_1

    .line 7
    .line 8
    :try_start_0
    monitor-exit v0

    .line 9
    return-object v2

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    goto/16 :goto_2

    .line 12
    .line 13
    :cond_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/util/Vector;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_2

    .line 20
    .line 21
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/util/Vector;->isEmpty()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-nez v3, :cond_3

    .line 28
    .line 29
    :cond_2
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 30
    .line 31
    invoke-virtual {v3}, Ljava/util/Vector;->isEmpty()Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_4

    .line 36
    .line 37
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 38
    .line 39
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 40
    .line 41
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getReceiveMaximum()Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    if-lt v3, v4, :cond_4

    .line 50
    .line 51
    :cond_3
    :try_start_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 52
    .line 53
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 54
    .line 55
    const-string v5, "get"

    .line 56
    .line 57
    const-string v6, "644"

    .line 58
    .line 59
    invoke-interface {v3, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 63
    .line 64
    invoke-virtual {v3}, Ljava/lang/Object;->wait()V

    .line 65
    .line 66
    .line 67
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 68
    .line 69
    const-string v5, "get"

    .line 70
    .line 71
    const-string v6, "647"

    .line 72
    .line 73
    invoke-interface {v3, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 74
    .line 75
    .line 76
    :catch_0
    :cond_4
    :try_start_2
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 77
    .line 78
    if-eqz v3, :cond_9

    .line 79
    .line 80
    iget-boolean v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->connected:Z

    .line 81
    .line 82
    const/4 v4, 0x0

    .line 83
    if-nez v3, :cond_5

    .line 84
    .line 85
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 86
    .line 87
    invoke-virtual {v3}, Ljava/util/Vector;->isEmpty()Z

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    if-nez v3, :cond_9

    .line 92
    .line 93
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 94
    .line 95
    invoke-virtual {v3, v4}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 100
    .line 101
    instance-of v3, v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 102
    .line 103
    if-nez v3, :cond_5

    .line 104
    .line 105
    goto/16 :goto_1

    .line 106
    .line 107
    :cond_5
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/util/Vector;->isEmpty()Z

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-nez v3, :cond_7

    .line 114
    .line 115
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 116
    .line 117
    invoke-virtual {v2, v4}, Ljava/util/Vector;->remove(I)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    check-cast v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 122
    .line 123
    instance-of v3, v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 124
    .line 125
    if-eqz v3, :cond_6

    .line 126
    .line 127
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 128
    .line 129
    add-int/lit8 v3, v3, 0x1

    .line 130
    .line 131
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 132
    .line 133
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 134
    .line 135
    sget-object v5, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 136
    .line 137
    const-string v6, "get"

    .line 138
    .line 139
    const-string v7, "617"

    .line 140
    .line 141
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-interface {v4, v5, v6, v7, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    :cond_6
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z

    .line 153
    .line 154
    .line 155
    goto/16 :goto_0

    .line 156
    .line 157
    :cond_7
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 158
    .line 159
    invoke-virtual {v3}, Ljava/util/Vector;->isEmpty()Z

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    if-nez v3, :cond_0

    .line 164
    .line 165
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 166
    .line 167
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 168
    .line 169
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getReceiveMaximum()Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 174
    .line 175
    .line 176
    move-result v5

    .line 177
    if-ge v3, v5, :cond_8

    .line 178
    .line 179
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 180
    .line 181
    invoke-virtual {v2, v4}, Ljava/util/Vector;->elementAt(I)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    check-cast v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 186
    .line 187
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 188
    .line 189
    invoke-virtual {v3, v4}, Ljava/util/Vector;->removeElementAt(I)V

    .line 190
    .line 191
    .line 192
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 193
    .line 194
    add-int/lit8 v3, v3, 0x1

    .line 195
    .line 196
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 197
    .line 198
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 199
    .line 200
    sget-object v5, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 201
    .line 202
    const-string v6, "get"

    .line 203
    .line 204
    const-string v7, "623"

    .line 205
    .line 206
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 207
    .line 208
    .line 209
    move-result-object v3

    .line 210
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v3

    .line 214
    invoke-interface {v4, v5, v6, v7, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_0

    .line 218
    .line 219
    :cond_8
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 220
    .line 221
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 222
    .line 223
    const-string v5, "get"

    .line 224
    .line 225
    const-string v6, "622"

    .line 226
    .line 227
    invoke-interface {v3, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    goto/16 :goto_0

    .line 231
    .line 232
    :cond_9
    :goto_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 233
    .line 234
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 235
    .line 236
    const-string v3, "get"

    .line 237
    .line 238
    const-string v4, "621"

    .line 239
    .line 240
    invoke-interface {p0, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    monitor-exit v0

    .line 244
    return-object v1

    .line 245
    :goto_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 246
    throw p0
.end method

.method public getActualInFlight()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 2
    .line 3
    return p0
.end method

.method public getCleanStart()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->cleanStart:Z

    .line 2
    .line 3
    return p0
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
    const-string v1, "In use msgids"

    .line 7
    .line 8
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    const-string v1, "pendingMessages"

    .line 14
    .line 15
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 16
    .line 17
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    const-string v1, "pendingFlows"

    .line 21
    .line 22
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 28
    .line 29
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getReceiveMaximum()Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 34
    .line 35
    .line 36
    const-string v2, "serverReceiveMaximum"

    .line 37
    .line 38
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 42
    .line 43
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    const-string v2, "nextMsgID"

    .line 48
    .line 49
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 53
    .line 54
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    const-string v2, "actualInFlight"

    .line 59
    .line 60
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 64
    .line 65
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    const-string v2, "inFlightPubRels"

    .line 70
    .line 71
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 75
    .line 76
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    const-string v2, "quiescing"

    .line 81
    .line 82
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 86
    .line 87
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    const-string v2, "pingoutstanding"

    .line 92
    .line 93
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    iget-wide v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 97
    .line 98
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    const-string v2, "lastOutboundActivity"

    .line 103
    .line 104
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    iget-wide v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 108
    .line 109
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    const-string v2, "lastInboundActivity"

    .line 114
    .line 115
    invoke-virtual {v0, v2, v1}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    const-string v1, "outboundQoS2"

    .line 119
    .line 120
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 121
    .line 122
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    const-string v1, "outboundQoS1"

    .line 126
    .line 127
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 128
    .line 129
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    const-string v1, "outboundQoS0"

    .line 133
    .line 134
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 135
    .line 136
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    const-string v1, "inboundQoS2"

    .line 140
    .line 141
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 142
    .line 143
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    const-string v1, "tokens"

    .line 147
    .line 148
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 149
    .line 150
    invoke-virtual {v0, v1, p0}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    return-object v0
.end method

.method public getIncomingMaximumPacketSize()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getOutgoingMaximumPacketSize()Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getOutgoingMaximumPacketSize()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getIncomingMaximumPacketSize()Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public handleInboundPubRel(Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    aget v0, v0, v1

    .line 7
    .line 8
    const/16 v2, 0x80

    .line 9
    .line 10
    const-string v3, "handleInboundPubRel"

    .line 11
    .line 12
    if-gt v0, v2, :cond_0

    .line 13
    .line 14
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    .line 15
    .line 16
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 21
    .line 22
    invoke-direct {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-direct {v0, v1, p1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 29
    .line 30
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    const-string v4, "668"

    .line 41
    .line 42
    invoke-interface {p1, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->info(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    const/4 p1, 0x0

    .line 46
    invoke-virtual {p0, v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 51
    .line 52
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    aget v5, v5, v1

    .line 71
    .line 72
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    filled-new-array {v2, v4, v5}, [Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    const-string v4, "667"

    .line 81
    .line 82
    invoke-interface {p0, v0, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 86
    .line 87
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    aget p1, p1, v1

    .line 92
    .line 93
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 94
    .line 95
    .line 96
    throw p0
.end method

.method public handleOrphanedAcks(Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    filled-new-array {v2, p1}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const-string v3, "handleOrphanedAcks"

    .line 18
    .line 19
    const-string v4, "666"

    .line 20
    .line 21
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    .line 25
    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 33
    .line 34
    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 38
    .line 39
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->isSendReasonMessages()Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

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
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    const-string v2, "Message identifier [%d] was not found. Discontinuing QoS 2 flow."

    .line 58
    .line 59
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setReasonString(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    :cond_0
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 67
    .line 68
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 73
    .line 74
    invoke-direct {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 75
    .line 76
    .line 77
    const/16 v2, 0x92

    .line 78
    .line 79
    invoke-direct {v0, v2, p1, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 80
    .line 81
    .line 82
    const/4 p1, 0x0

    .line 83
    invoke-virtual {p0, v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 84
    .line 85
    .line 86
    :cond_1
    return-void
.end method

.method public notifyComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 5

    .line 1
    iget-object v0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getWireMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    instance-of v1, v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 10
    .line 11
    if-eqz v1, :cond_2

    .line 12
    .line 13
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 14
    .line 15
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    filled-new-array {v3, p1, v0}, [Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    const-string v3, "notifyComplete"

    .line 30
    .line 31
    const-string v4, "629"

    .line 32
    .line 33
    invoke-interface {v1, v2, v3, v4, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    move-object p1, v0

    .line 37
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 38
    .line 39
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    .line 40
    .line 41
    if-eqz v1, :cond_0

    .line 42
    .line 43
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 44
    .line 45
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-interface {v1, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 53
    .line 54
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendBufferedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    invoke-interface {v1, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 62
    .line 63
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    invoke-virtual {v1, v4}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->decrementInFlight()V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    invoke-direct {p0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->releaseMessageId(I)V

    .line 82
    .line 83
    .line 84
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 85
    .line 86
    invoke-virtual {v1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 87
    .line 88
    .line 89
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 90
    .line 91
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    const-string v1, "650"

    .line 104
    .line 105
    invoke-interface {v0, v2, v3, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_0
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    .line 110
    .line 111
    if-eqz v1, :cond_1

    .line 112
    .line 113
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 114
    .line 115
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    invoke-interface {v1, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 123
    .line 124
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendConfirmPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    invoke-interface {v1, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 132
    .line 133
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendBufferedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    invoke-interface {v1, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 141
    .line 142
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    invoke-virtual {v1, v4}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 154
    .line 155
    add-int/lit8 v1, v1, -0x1

    .line 156
    .line 157
    iput v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 158
    .line 159
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->decrementInFlight()V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    invoke-direct {p0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->releaseMessageId(I)V

    .line 167
    .line 168
    .line 169
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 170
    .line 171
    invoke-virtual {v1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 172
    .line 173
    .line 174
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 175
    .line 176
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 177
    .line 178
    .line 179
    move-result p1

    .line 180
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 185
    .line 186
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    filled-new-array {p1, v1}, [Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object p1

    .line 194
    const-string v1, "645"

    .line 195
    .line 196
    invoke-interface {v0, v2, v3, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z

    .line 200
    .line 201
    .line 202
    :cond_2
    return-void
.end method

.method public notifyQueueLock()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    const-string v3, "notifyQueueLock"

    .line 9
    .line 10
    const-string v4, "638"

    .line 11
    .line 12
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 18
    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    throw p0
.end method

.method public notifyReceivedAck(Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;)V
    .locals 7

    .line 1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 6
    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 8
    .line 9
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 10
    .line 11
    const-string v2, "notifyReceivedAck"

    .line 12
    .line 13
    const-string v3, "627"

    .line 14
    .line 15
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    filled-new-array {v4, p1}, [Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 39
    .line 40
    const-string v2, "notifyReceivedAck"

    .line 41
    .line 42
    const-string v3, "662"

    .line 43
    .line 44
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-interface {v0, v1, v2, v3, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_5

    .line 60
    .line 61
    :cond_0
    instance-of v2, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 62
    .line 63
    const/4 v3, 0x0

    .line 64
    const/4 v4, 0x0

    .line 65
    if-eqz v2, :cond_2

    .line 66
    .line 67
    move-object v2, p1

    .line 68
    check-cast v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 69
    .line 70
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    aget v5, v5, v3

    .line 75
    .line 76
    const/16 v6, 0x80

    .line 77
    .line 78
    if-gt v5, v6, :cond_1

    .line 79
    .line 80
    invoke-virtual {p0, p1, v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->updateResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 81
    .line 82
    .line 83
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 84
    .line 85
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 90
    .line 91
    invoke-direct {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 92
    .line 93
    .line 94
    invoke-direct {v1, v3, p1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0, v1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 98
    .line 99
    .line 100
    goto/16 :goto_5

    .line 101
    .line 102
    :cond_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 103
    .line 104
    const-string v0, "notifyReceivedAck"

    .line 105
    .line 106
    const-string v4, "664"

    .line 107
    .line 108
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 109
    .line 110
    .line 111
    move-result v5

    .line 112
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    aget v6, v6, v3

    .line 121
    .line 122
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 123
    .line 124
    .line 125
    move-result-object v6

    .line 126
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    filled-new-array {v5, v6, p1}, [Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    invoke-interface {p0, v1, v0, v4, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 138
    .line 139
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    aget p1, p1, v3

    .line 144
    .line 145
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_2
    instance-of v2, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    .line 150
    .line 151
    if-nez v2, :cond_9

    .line 152
    .line 153
    instance-of v2, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    .line 154
    .line 155
    if-eqz v2, :cond_3

    .line 156
    .line 157
    goto/16 :goto_4

    .line 158
    .line 159
    :cond_3
    instance-of v2, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingResp;

    .line 160
    .line 161
    if-eqz v2, :cond_5

    .line 162
    .line 163
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstandingLock:Ljava/lang/Object;

    .line 164
    .line 165
    monitor-enter v2

    .line 166
    :try_start_0
    iget v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 167
    .line 168
    add-int/lit8 v5, v5, -0x1

    .line 169
    .line 170
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 171
    .line 172
    .line 173
    move-result v3

    .line 174
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 175
    .line 176
    invoke-virtual {p0, p1, v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 177
    .line 178
    .line 179
    iget v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 180
    .line 181
    if-nez v0, :cond_4

    .line 182
    .line 183
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 184
    .line 185
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 186
    .line 187
    .line 188
    goto :goto_0

    .line 189
    :catchall_0
    move-exception p0

    .line 190
    goto :goto_1

    .line 191
    :cond_4
    :goto_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 192
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 193
    .line 194
    const-string v0, "notifyReceivedAck"

    .line 195
    .line 196
    const-string v2, "636"

    .line 197
    .line 198
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 199
    .line 200
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    invoke-interface {p1, v1, v0, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    goto :goto_5

    .line 212
    :goto_1
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 213
    throw p0

    .line 214
    :cond_5
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;

    .line 215
    .line 216
    if-eqz v1, :cond_8

    .line 217
    .line 218
    move-object v1, p1

    .line 219
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;

    .line 220
    .line 221
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->getReturnCode()I

    .line 222
    .line 223
    .line 224
    move-result v2

    .line 225
    if-nez v2, :cond_7

    .line 226
    .line 227
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 228
    .line 229
    monitor-enter v5

    .line 230
    :try_start_2
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->cleanStart:Z

    .line 231
    .line 232
    if-eqz v2, :cond_6

    .line 233
    .line 234
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clearState()V

    .line 235
    .line 236
    .line 237
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 238
    .line 239
    invoke-virtual {v2, v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 240
    .line 241
    .line 242
    goto :goto_2

    .line 243
    :catchall_1
    move-exception p0

    .line 244
    goto :goto_3

    .line 245
    :cond_6
    :goto_2
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 246
    .line 247
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 248
    .line 249
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->restoreInflightMessages()V

    .line 250
    .line 251
    .line 252
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->connected()V

    .line 253
    .line 254
    .line 255
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 256
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 257
    .line 258
    invoke-virtual {v2, v1, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->connectComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {p0, p1, v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 262
    .line 263
    .line 264
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 265
    .line 266
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 267
    .line 268
    .line 269
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 270
    .line 271
    monitor-enter p1

    .line 272
    :try_start_3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 273
    .line 274
    invoke-virtual {v0}, Ljava/lang/Object;->notifyAll()V

    .line 275
    .line 276
    .line 277
    monitor-exit p1

    .line 278
    goto :goto_5

    .line 279
    :catchall_2
    move-exception p0

    .line 280
    monitor-exit p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 281
    throw p0

    .line 282
    :goto_3
    :try_start_4
    monitor-exit v5
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 283
    throw p0

    .line 284
    :cond_7
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    throw p0

    .line 289
    :cond_8
    invoke-virtual {p0, p1, v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 293
    .line 294
    .line 295
    move-result v0

    .line 296
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->releaseMessageId(I)V

    .line 297
    .line 298
    .line 299
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 300
    .line 301
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 302
    .line 303
    .line 304
    goto :goto_5

    .line 305
    :cond_9
    :goto_4
    invoke-virtual {p0, p1, v0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 306
    .line 307
    .line 308
    :goto_5
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z

    .line 309
    .line 310
    .line 311
    return-void
.end method

.method public notifyReceivedBytes(I)V
    .locals 3

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 8
    .line 9
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 10
    .line 11
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    const-string v1, "notifyReceivedBytes"

    .line 22
    .line 23
    const-string v2, "630"

    .line 24
    .line 25
    invoke-interface {p0, v0, v1, v2, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public notifyReceivedMsg(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 6

    .line 1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastInboundActivity:J

    .line 6
    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 8
    .line 9
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    filled-new-array {v2, p1}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-string v3, "notifyReceivedMsg"

    .line 24
    .line 25
    const-string v4, "651"

    .line 26
    .line 27
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 31
    .line 32
    if-nez v0, :cond_b

    .line 33
    .line 34
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 35
    .line 36
    if-eqz v0, :cond_9

    .line 37
    .line 38
    move-object v0, p1

    .line 39
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 40
    .line 41
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    if-eqz v2, :cond_5

    .line 50
    .line 51
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 64
    .line 65
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getIncomingTopicAliasMax()Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    if-gt v4, v5, :cond_3

    .line 74
    .line 75
    if-nez v4, :cond_0

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_0
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    if-eqz v4, :cond_1

    .line 83
    .line 84
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 85
    .line 86
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    filled-new-array {v4, v5}, [Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    const-string v5, "652"

    .line 106
    .line 107
    invoke-interface {v2, v1, v3, v5, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->incomingTopicAliases:Ljava/util/Hashtable;

    .line 111
    .line 112
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    invoke-virtual {v1, v2, v3}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_1
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->incomingTopicAliases:Ljava/util/Hashtable;

    .line 129
    .line 130
    invoke-virtual {v4, v2}, Ljava/util/Hashtable;->contains(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v4

    .line 134
    if-eqz v4, :cond_2

    .line 135
    .line 136
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->incomingTopicAliases:Ljava/util/Hashtable;

    .line 137
    .line 138
    invoke-virtual {v1, v2}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    check-cast v1, Ljava/lang/String;

    .line 143
    .line 144
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->setTopicName(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 149
    .line 150
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 159
    .line 160
    .line 161
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    const-string v0, "654"

    .line 166
    .line 167
    invoke-interface {p0, v1, v3, v0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 171
    .line 172
    const/16 p1, 0x7e2e

    .line 173
    .line 174
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 175
    .line 176
    .line 177
    throw p0

    .line 178
    :cond_3
    :goto_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 179
    .line 180
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 181
    .line 182
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getIncomingTopicAliasMax()Ljava/lang/Integer;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 187
    .line 188
    .line 189
    filled-new-array {v0, v2}, [Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    const-string v2, "653"

    .line 194
    .line 195
    invoke-interface {p1, v1, v3, v2, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 199
    .line 200
    if-eqz p0, :cond_4

    .line 201
    .line 202
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 203
    .line 204
    const v0, 0xc354

    .line 205
    .line 206
    .line 207
    invoke-direct {p1, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttErrorOccurred(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 211
    .line 212
    .line 213
    :cond_4
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 214
    .line 215
    const/16 p1, 0x7e2d

    .line 216
    .line 217
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 218
    .line 219
    .line 220
    throw p0

    .line 221
    :cond_5
    :goto_1
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    if-eqz v1, :cond_8

    .line 230
    .line 231
    const/4 v2, 0x1

    .line 232
    if-eq v1, v2, :cond_8

    .line 233
    .line 234
    const/4 v2, 0x2

    .line 235
    if-eq v1, v2, :cond_6

    .line 236
    .line 237
    goto :goto_2

    .line 238
    :cond_6
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 239
    .line 240
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getReceivedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    invoke-interface {v1, p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V

    .line 245
    .line 246
    .line 247
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 248
    .line 249
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    invoke-virtual {p1, v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 261
    .line 262
    if-eqz p1, :cond_7

    .line 263
    .line 264
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageArrived(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V

    .line 265
    .line 266
    .line 267
    :cond_7
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 268
    .line 269
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 270
    .line 271
    .line 272
    move-result v0

    .line 273
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 274
    .line 275
    invoke-direct {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 276
    .line 277
    .line 278
    const/4 v2, 0x0

    .line 279
    invoke-direct {p1, v2, v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 280
    .line 281
    .line 282
    const/4 v0, 0x0

    .line 283
    invoke-virtual {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 284
    .line 285
    .line 286
    return-void

    .line 287
    :cond_8
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 288
    .line 289
    if-eqz p0, :cond_b

    .line 290
    .line 291
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageArrived(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V

    .line 292
    .line 293
    .line 294
    return-void

    .line 295
    :cond_9
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 296
    .line 297
    if-eqz v0, :cond_a

    .line 298
    .line 299
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 300
    .line 301
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->handleInboundPubRel(Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;)V

    .line 302
    .line 303
    .line 304
    return-void

    .line 305
    :cond_a
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;

    .line 306
    .line 307
    if-eqz v0, :cond_b

    .line 308
    .line 309
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;

    .line 310
    .line 311
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 312
    .line 313
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->authMessageReceived(Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;)V

    .line 314
    .line 315
    .line 316
    :cond_b
    :goto_2
    return-void
.end method

.method public notifyResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 5

    .line 1
    iget-object v0, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 7
    .line 8
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifyComplete()V

    .line 9
    .line 10
    .line 11
    const-string v0, "notifyResult"

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 20
    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 24
    .line 25
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v3, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 28
    .line 29
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    filled-new-array {v3, p1, p3}, [Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    const-string v4, "648"

    .line 38
    .line 39
    invoke-interface {v1, v2, v0, v4, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 43
    .line 44
    invoke-virtual {v1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->asyncOperationComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 45
    .line 46
    .line 47
    :cond_0
    if-nez p1, :cond_1

    .line 48
    .line 49
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 50
    .line 51
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 52
    .line 53
    iget-object v2, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 54
    .line 55
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    filled-new-array {v2, p3}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p3

    .line 63
    const-string v2, "649"

    .line 64
    .line 65
    invoke-interface {p1, v1, v0, v2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 69
    .line 70
    invoke-virtual {p0, p2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->asyncOperationComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 71
    .line 72
    .line 73
    :cond_1
    return-void
.end method

.method public notifySent(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 5

    .line 1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 6
    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 8
    .line 9
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 10
    .line 11
    const-string v2, "notifySent"

    .line 12
    .line 13
    const-string v3, "625"

    .line 14
    .line 15
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-nez v0, :cond_0

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    iget-object v2, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 36
    .line 37
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifySent()V

    .line 38
    .line 39
    .line 40
    instance-of v2, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingReq;

    .line 41
    .line 42
    if-eqz v2, :cond_1

    .line 43
    .line 44
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstandingLock:Ljava/lang/Object;

    .line 45
    .line 46
    monitor-enter v2

    .line 47
    :try_start_0
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 48
    .line 49
    .line 50
    move-result-wide v3

    .line 51
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstandingLock:Ljava/lang/Object;

    .line 52
    .line 53
    monitor-enter p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    :try_start_1
    iput-wide v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastPing:J

    .line 55
    .line 56
    iget v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 57
    .line 58
    add-int/lit8 v0, v0, 0x1

    .line 59
    .line 60
    iput v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingOutstanding:I

    .line 61
    .line 62
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 63
    :try_start_2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 64
    .line 65
    const-string p1, "notifySent"

    .line 66
    .line 67
    const-string v3, "635"

    .line 68
    .line 69
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-interface {p0, v1, p1, v3, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 81
    return-void

    .line 82
    :catchall_0
    move-exception p0

    .line 83
    goto :goto_0

    .line 84
    :catchall_1
    move-exception p0

    .line 85
    :try_start_3
    monitor-exit p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 86
    :try_start_4
    throw p0

    .line 87
    :goto_0
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 88
    throw p0

    .line 89
    :cond_1
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 90
    .line 91
    if-eqz v1, :cond_2

    .line 92
    .line 93
    move-object v1, p1

    .line 94
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 95
    .line 96
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_2

    .line 105
    .line 106
    iget-object v1, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 107
    .line 108
    const/4 v2, 0x0

    .line 109
    invoke-virtual {v1, v2, v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 110
    .line 111
    .line 112
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 113
    .line 114
    invoke-virtual {v1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->asyncOperationComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 115
    .line 116
    .line 117
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->decrementInFlight()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->releaseMessageId(I)V

    .line 125
    .line 126
    .line 127
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 128
    .line 129
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z

    .line 133
    .line 134
    .line 135
    :cond_2
    :goto_1
    return-void
.end method

.method public notifySentBytes(I)V
    .locals 3

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->lastOutboundActivity:J

    .line 8
    .line 9
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 10
    .line 11
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    const-string v1, "notifySentBytes"

    .line 22
    .line 23
    const-string v2, "643"

    .line 24
    .line 25
    invoke-interface {p0, v0, v1, v2, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public persistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 6

    .line 1
    const-string v0, "513"

    .line 2
    .line 3
    const-string v1, "persistBufferedMessage"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendBufferedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    :try_start_0
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getNextMessageId()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {p1, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setMessageId(I)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendBufferedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v2
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_1

    .line 20
    :try_start_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 21
    .line 22
    move-object v4, p1

    .line 23
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 24
    .line 25
    invoke-interface {v3, v2, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V
    :try_end_1
    .catch Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_1 .. :try_end_1} :catch_1

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catch_0
    :try_start_2
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 30
    .line 31
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 32
    .line 33
    const-string v5, "515"

    .line 34
    .line 35
    invoke-interface {v3, v4, v1, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 39
    .line 40
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 41
    .line 42
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    invoke-interface {v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    invoke-interface {v3, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->open(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 54
    .line 55
    check-cast p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 56
    .line 57
    invoke-interface {v3, v2, p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V

    .line 58
    .line 59
    .line 60
    :goto_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 61
    .line 62
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 63
    .line 64
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-interface {p1, v3, v1, v0, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_2 .. :try_end_2} :catch_1

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :catch_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 73
    .line 74
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 75
    .line 76
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-interface {p0, p1, v1, v0, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->warning(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :goto_1
    return-void
.end method

.method public quiesce(J)V
    .locals 9

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-lez v0, :cond_2

    .line 6
    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 8
    .line 9
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 10
    .line 11
    const-string v2, "quiesce"

    .line 12
    .line 13
    const-string v3, "637"

    .line 14
    .line 15
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 27
    .line 28
    monitor-enter v0

    .line 29
    const/4 v2, 0x1

    .line 30
    :try_start_0
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 31
    .line 32
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 33
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 34
    .line 35
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->quiesce()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyQueueLock()V

    .line 39
    .line 40
    .line 41
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesceLock:Ljava/lang/Object;

    .line 42
    .line 43
    monitor-enter v2

    .line 44
    :try_start_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 45
    .line 46
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->count()I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-gtz v0, :cond_0

    .line 51
    .line 52
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 53
    .line 54
    invoke-virtual {v3}, Ljava/util/Vector;->size()I

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-gtz v3, :cond_0

    .line 59
    .line 60
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->callback:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 61
    .line 62
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiesced()Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-nez v3, :cond_1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :catchall_0
    move-exception p0

    .line 70
    goto :goto_1

    .line 71
    :cond_0
    :goto_0
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 72
    .line 73
    const-string v4, "quiesce"

    .line 74
    .line 75
    const-string v5, "639"

    .line 76
    .line 77
    iget v6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 78
    .line 79
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object v6

    .line 83
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 84
    .line 85
    invoke-virtual {v7}, Ljava/util/Vector;->size()I

    .line 86
    .line 87
    .line 88
    move-result v7

    .line 89
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    iget v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inFlightPubRels:I

    .line 94
    .line 95
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    filled-new-array {v6, v7, v8, v0}, [Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-interface {v3, v1, v4, v5, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesceLock:Ljava/lang/Object;

    .line 111
    .line 112
    invoke-virtual {v0, p1, p2}, Ljava/lang/Object;->wait(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 113
    .line 114
    .line 115
    :catch_0
    :cond_1
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 116
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 117
    .line 118
    monitor-enter p1

    .line 119
    :try_start_3
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 120
    .line 121
    invoke-virtual {p2}, Ljava/util/Vector;->clear()V

    .line 122
    .line 123
    .line 124
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 125
    .line 126
    invoke-virtual {p2}, Ljava/util/Vector;->clear()V

    .line 127
    .line 128
    .line 129
    const/4 p2, 0x0

    .line 130
    iput-boolean p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiescing:Z

    .line 131
    .line 132
    iput p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 133
    .line 134
    monitor-exit p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 135
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 136
    .line 137
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 138
    .line 139
    const-string p2, "quiesce"

    .line 140
    .line 141
    const-string v0, "640"

    .line 142
    .line 143
    invoke-interface {p0, p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    return-void

    .line 147
    :catchall_1
    move-exception p0

    .line 148
    :try_start_4
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 149
    throw p0

    .line 150
    :goto_1
    :try_start_5
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 151
    throw p0

    .line 152
    :catchall_2
    move-exception p0

    .line 153
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 154
    throw p0

    .line 155
    :cond_2
    return-void
.end method

.method public resolveOldTokens(Lorg/eclipse/paho/mqttv5/common/MqttException;)Ljava/util/Vector;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/eclipse/paho/mqttv5/common/MqttException;",
            ")",
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/client/MqttToken;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "resolveOldTokens"

    .line 6
    .line 7
    const-string v3, "632"

    .line 8
    .line 9
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    if-nez p1, :cond_0

    .line 17
    .line 18
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 19
    .line 20
    const/16 v0, 0x7d66

    .line 21
    .line 22
    invoke-direct {p1, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 26
    .line 27
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getOutstandingTokens()Ljava/util/Vector;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Ljava/util/Vector;->elements()Ljava/util/Enumeration;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-nez v2, :cond_2

    .line 40
    .line 41
    return-object v0

    .line 42
    :cond_2
    invoke-interface {v1}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 47
    .line 48
    monitor-enter v2

    .line 49
    :try_start_0
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->isComplete()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-nez v3, :cond_3

    .line 54
    .line 55
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 56
    .line 57
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isCompletePending()Z

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    if-nez v3, :cond_3

    .line 62
    .line 63
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    if-nez v3, :cond_3

    .line 68
    .line 69
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 70
    .line 71
    invoke-virtual {v3, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setException(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :catchall_0
    move-exception p0

    .line 76
    goto :goto_2

    .line 77
    :cond_3
    :goto_1
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 79
    .line 80
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isDeliveryToken()Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-nez v3, :cond_1

    .line 85
    .line 86
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 87
    .line 88
    iget-object v2, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 89
    .line 90
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-virtual {v3, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :goto_2
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 99
    throw p0
.end method

.method public restoreState()V
    .locals 13

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 2
    .line 3
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->keys()Ljava/util/Enumeration;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 8
    .line 9
    new-instance v2, Ljava/util/Vector;

    .line 10
    .line 11
    invoke-direct {v2}, Ljava/util/Vector;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 15
    .line 16
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 17
    .line 18
    const-string v5, "600"

    .line 19
    .line 20
    const-string v6, "restoreState"

    .line 21
    .line 22
    invoke-interface {v3, v4, v6, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-nez v3, :cond_2

    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/util/Vector;->elements()Ljava/util/Enumeration;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    :goto_1
    invoke-interface {v3}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_1

    .line 40
    .line 41
    iput v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->nextMsgId:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-interface {v3}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Ljava/lang/String;

    .line 49
    .line 50
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 51
    .line 52
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 53
    .line 54
    const-string v5, "609"

    .line 55
    .line 56
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    invoke-interface {v2, v4, v6, v5, v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 64
    .line 65
    invoke-interface {v2, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    invoke-interface {v0}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    check-cast v3, Ljava/lang/String;

    .line 74
    .line 75
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 76
    .line 77
    invoke-interface {v4, v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->get(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/common/MqttPersistable;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    invoke-direct {p0, v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->restoreMessage(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    if-eqz v4, :cond_0

    .line 86
    .line 87
    const-string v5, "r-"

    .line 88
    .line 89
    invoke-virtual {v3, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 90
    .line 91
    .line 92
    move-result v5

    .line 93
    if-eqz v5, :cond_3

    .line 94
    .line 95
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 96
    .line 97
    sget-object v7, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 98
    .line 99
    const-string v8, "604"

    .line 100
    .line 101
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-interface {v5, v7, v6, v8, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 109
    .line 110
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 111
    .line 112
    .line 113
    move-result v5

    .line 114
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    invoke-virtual {v3, v5, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_3
    const-string v5, "s-"

    .line 123
    .line 124
    invoke-virtual {v3, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    const-string v7, "608"

    .line 129
    .line 130
    const-string v8, "607"

    .line 131
    .line 132
    const/4 v9, 0x2

    .line 133
    const/4 v10, 0x1

    .line 134
    if-eqz v5, :cond_7

    .line 135
    .line 136
    move-object v5, v4

    .line 137
    check-cast v5, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 138
    .line 139
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 140
    .line 141
    .line 142
    move-result v11

    .line 143
    invoke-static {v11, v1}, Ljava/lang/Math;->max(II)I

    .line 144
    .line 145
    .line 146
    move-result v1

    .line 147
    iget-object v11, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 148
    .line 149
    invoke-direct {p0, v5}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendConfirmPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v12

    .line 153
    invoke-interface {v11, v12}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->containsKey(Ljava/lang/String;)Z

    .line 154
    .line 155
    .line 156
    move-result v11

    .line 157
    if-eqz v11, :cond_5

    .line 158
    .line 159
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 160
    .line 161
    invoke-direct {p0, v5}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendConfirmPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v8

    .line 165
    invoke-interface {v7, v8}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->get(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/common/MqttPersistable;

    .line 166
    .line 167
    .line 168
    move-result-object v7

    .line 169
    invoke-direct {p0, v3, v7}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->restoreMessage(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 170
    .line 171
    .line 172
    move-result-object v7

    .line 173
    check-cast v7, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 174
    .line 175
    if-eqz v7, :cond_4

    .line 176
    .line 177
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 178
    .line 179
    sget-object v9, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 180
    .line 181
    const-string v10, "605"

    .line 182
    .line 183
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    invoke-interface {v8, v9, v6, v10, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 191
    .line 192
    invoke-virtual {v7}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 193
    .line 194
    .line 195
    move-result v4

    .line 196
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    invoke-virtual {v3, v4, v7}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_4
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 205
    .line 206
    sget-object v8, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 207
    .line 208
    const-string v9, "606"

    .line 209
    .line 210
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v3

    .line 214
    invoke-interface {v7, v8, v6, v9, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    goto :goto_2

    .line 218
    :cond_5
    invoke-virtual {v5, v10}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setDuplicate(Z)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 222
    .line 223
    .line 224
    move-result-object v10

    .line 225
    invoke-virtual {v10}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 226
    .line 227
    .line 228
    move-result v10

    .line 229
    if-ne v10, v9, :cond_6

    .line 230
    .line 231
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 232
    .line 233
    sget-object v9, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 234
    .line 235
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    invoke-interface {v7, v9, v6, v8, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 243
    .line 244
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    goto :goto_2

    .line 256
    :cond_6
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 257
    .line 258
    sget-object v9, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 259
    .line 260
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v3

    .line 264
    invoke-interface {v8, v9, v6, v7, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 265
    .line 266
    .line 267
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 268
    .line 269
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 270
    .line 271
    .line 272
    move-result v4

    .line 273
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    :goto_2
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 281
    .line 282
    invoke-virtual {v3, v5}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->restoreToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 283
    .line 284
    .line 285
    move-result-object v3

    .line 286
    iget-object v3, v3, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 287
    .line 288
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 289
    .line 290
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 291
    .line 292
    .line 293
    move-result-object v4

    .line 294
    invoke-virtual {v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V

    .line 295
    .line 296
    .line 297
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 298
    .line 299
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 300
    .line 301
    .line 302
    move-result v4

    .line 303
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 304
    .line 305
    .line 306
    move-result-object v4

    .line 307
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 308
    .line 309
    .line 310
    move-result v5

    .line 311
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 312
    .line 313
    .line 314
    move-result-object v5

    .line 315
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    goto/16 :goto_0

    .line 319
    .line 320
    :cond_7
    const-string v5, "sb-"

    .line 321
    .line 322
    invoke-virtual {v3, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 323
    .line 324
    .line 325
    move-result v5

    .line 326
    if-eqz v5, :cond_a

    .line 327
    .line 328
    move-object v5, v4

    .line 329
    check-cast v5, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 330
    .line 331
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 332
    .line 333
    .line 334
    move-result v11

    .line 335
    invoke-static {v11, v1}, Ljava/lang/Math;->max(II)I

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 340
    .line 341
    .line 342
    move-result-object v11

    .line 343
    invoke-virtual {v11}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 344
    .line 345
    .line 346
    move-result v11

    .line 347
    if-ne v11, v9, :cond_8

    .line 348
    .line 349
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 350
    .line 351
    sget-object v9, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 352
    .line 353
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v3

    .line 357
    invoke-interface {v7, v9, v6, v8, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 358
    .line 359
    .line 360
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 361
    .line 362
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 363
    .line 364
    .line 365
    move-result v4

    .line 366
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 367
    .line 368
    .line 369
    move-result-object v4

    .line 370
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    goto :goto_3

    .line 374
    :cond_8
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 375
    .line 376
    .line 377
    move-result-object v8

    .line 378
    invoke-virtual {v8}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 379
    .line 380
    .line 381
    move-result v8

    .line 382
    if-ne v8, v10, :cond_9

    .line 383
    .line 384
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 385
    .line 386
    sget-object v9, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 387
    .line 388
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v3

    .line 392
    invoke-interface {v8, v9, v6, v7, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 393
    .line 394
    .line 395
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 396
    .line 397
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 398
    .line 399
    .line 400
    move-result v4

    .line 401
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 402
    .line 403
    .line 404
    move-result-object v4

    .line 405
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    goto :goto_3

    .line 409
    :cond_9
    iget-object v7, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 410
    .line 411
    sget-object v8, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 412
    .line 413
    const-string v9, "511"

    .line 414
    .line 415
    filled-new-array {v3, v4}, [Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v4

    .line 419
    invoke-interface {v7, v8, v6, v9, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 420
    .line 421
    .line 422
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS0:Ljava/util/concurrent/ConcurrentHashMap;

    .line 423
    .line 424
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 425
    .line 426
    .line 427
    move-result v7

    .line 428
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 429
    .line 430
    .line 431
    move-result-object v7

    .line 432
    invoke-virtual {v4, v7, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 436
    .line 437
    invoke-interface {v4, v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    :goto_3
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 441
    .line 442
    invoke-virtual {v3, v5}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->restoreToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 443
    .line 444
    .line 445
    move-result-object v3

    .line 446
    iget-object v3, v3, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 447
    .line 448
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 449
    .line 450
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 451
    .line 452
    .line 453
    move-result-object v4

    .line 454
    invoke-virtual {v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V

    .line 455
    .line 456
    .line 457
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->inUseMsgIds:Ljava/util/concurrent/ConcurrentHashMap;

    .line 458
    .line 459
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 460
    .line 461
    .line 462
    move-result v4

    .line 463
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 464
    .line 465
    .line 466
    move-result-object v4

    .line 467
    invoke-virtual {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 468
    .line 469
    .line 470
    move-result v5

    .line 471
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 472
    .line 473
    .line 474
    move-result-object v5

    .line 475
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 476
    .line 477
    .line 478
    goto/16 :goto_0

    .line 479
    .line 480
    :cond_a
    const-string v5, "sc-"

    .line 481
    .line 482
    invoke-virtual {v3, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 483
    .line 484
    .line 485
    move-result v5

    .line 486
    if-eqz v5, :cond_0

    .line 487
    .line 488
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 489
    .line 490
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 491
    .line 492
    invoke-direct {p0, v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object v4

    .line 496
    invoke-interface {v5, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->containsKey(Ljava/lang/String;)Z

    .line 497
    .line 498
    .line 499
    move-result v4

    .line 500
    if-nez v4, :cond_0

    .line 501
    .line 502
    invoke-virtual {v2, v3}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 503
    .line 504
    .line 505
    goto/16 :goto_0
.end method

.method public send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->isMessageIdRequired()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getNextMessageId()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setMessageId(I)V

    .line 18
    .line 19
    .line 20
    :cond_0
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 21
    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    move-object v1, p1

    .line 25
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 26
    .line 27
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 34
    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getOutgoingTopicAliasMaximum()Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-lez v2, :cond_2

    .line 46
    .line 47
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outgoingTopicAliases:Ljava/util/Hashtable;

    .line 52
    .line 53
    invoke-virtual {v3, v2}, Ljava/util/Hashtable;->containsKey(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_1

    .line 58
    .line 59
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outgoingTopicAliases:Ljava/util/Hashtable;

    .line 64
    .line 65
    invoke-virtual {v4, v2}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    check-cast v2, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {v3, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setTopicAlias(Ljava/lang/Integer;)V

    .line 72
    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->setTopicName(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 80
    .line 81
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getNextOutgoingTopicAlias()Ljava/lang/Integer;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 90
    .line 91
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getOutgoingTopicAliasMaximum()Ljava/lang/Integer;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-gt v3, v4, :cond_2

    .line 100
    .line 101
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-virtual {v3, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setTopicAlias(Ljava/lang/Integer;)V

    .line 106
    .line 107
    .line 108
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outgoingTopicAliases:Ljava/util/Hashtable;

    .line 109
    .line 110
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v3, v1, v2}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    :cond_2
    :goto_0
    if-eqz p2, :cond_3

    .line 118
    .line 119
    :try_start_0
    iget-object v1, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 120
    .line 121
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setMessageID(I)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 126
    .line 127
    .line 128
    :catch_0
    :cond_3
    if-eqz v0, :cond_7

    .line 129
    .line 130
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 131
    .line 132
    monitor-enter v0

    .line 133
    :try_start_1
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 134
    .line 135
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->mqttConnection:Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;

    .line 136
    .line 137
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->getReceiveMaximum()Ljava/lang/Integer;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    if-ge v1, v2, :cond_6

    .line 146
    .line 147
    move-object v1, p1

    .line 148
    check-cast v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 149
    .line 150
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 155
    .line 156
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 157
    .line 158
    const-string v4, "send"

    .line 159
    .line 160
    const-string v5, "628"

    .line 161
    .line 162
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 171
    .line 172
    .line 173
    move-result v7

    .line 174
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object v7

    .line 178
    filled-new-array {v6, v7, p1}, [Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v6

    .line 182
    invoke-interface {v2, v3, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    const/4 v2, 0x1

    .line 190
    if-eq v1, v2, :cond_5

    .line 191
    .line 192
    const/4 v2, 0x2

    .line 193
    if-eq v1, v2, :cond_4

    .line 194
    .line 195
    goto :goto_1

    .line 196
    :cond_4
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 197
    .line 198
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 203
    .line 204
    .line 205
    move-result-object v2

    .line 206
    invoke-virtual {v1, v2, p1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 210
    .line 211
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    move-object v3, p1

    .line 216
    check-cast v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 217
    .line 218
    invoke-interface {v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V

    .line 219
    .line 220
    .line 221
    goto :goto_1

    .line 222
    :catchall_0
    move-exception p0

    .line 223
    goto :goto_2

    .line 224
    :cond_5
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 225
    .line 226
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 227
    .line 228
    .line 229
    move-result v2

    .line 230
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    invoke-virtual {v1, v2, p1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 238
    .line 239
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v2

    .line 243
    move-object v3, p1

    .line 244
    check-cast v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 245
    .line 246
    invoke-interface {v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V

    .line 247
    .line 248
    .line 249
    :goto_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 250
    .line 251
    invoke-virtual {v1, p2, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 252
    .line 253
    .line 254
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 255
    .line 256
    invoke-virtual {p2, p1}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 260
    .line 261
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 262
    .line 263
    .line 264
    monitor-exit v0

    .line 265
    goto/16 :goto_5

    .line 266
    .line 267
    :cond_6
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 268
    .line 269
    sget-object p2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 270
    .line 271
    const-string v1, "send"

    .line 272
    .line 273
    const-string v2, "613"

    .line 274
    .line 275
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->actualInFlight:I

    .line 276
    .line 277
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 278
    .line 279
    .line 280
    move-result-object p0

    .line 281
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    invoke-interface {p1, p2, v1, v2, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 286
    .line 287
    .line 288
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 289
    .line 290
    const/16 p1, 0x7dca

    .line 291
    .line 292
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 293
    .line 294
    .line 295
    throw p0

    .line 296
    :goto_2
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 297
    throw p0

    .line 298
    :cond_7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 299
    .line 300
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 301
    .line 302
    const-string v2, "send"

    .line 303
    .line 304
    const-string v3, "615"

    .line 305
    .line 306
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 307
    .line 308
    .line 309
    move-result v4

    .line 310
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 311
    .line 312
    .line 313
    move-result-object v4

    .line 314
    filled-new-array {v4, p1}, [Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v4

    .line 318
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 322
    .line 323
    if-eqz v0, :cond_8

    .line 324
    .line 325
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 326
    .line 327
    monitor-enter v0

    .line 328
    :try_start_2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 329
    .line 330
    invoke-virtual {v1, p2, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 331
    .line 332
    .line 333
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 334
    .line 335
    const/4 v1, 0x0

    .line 336
    invoke-virtual {p2, p1, v1}, Ljava/util/Vector;->insertElementAt(Ljava/lang/Object;I)V

    .line 337
    .line 338
    .line 339
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 340
    .line 341
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 342
    .line 343
    .line 344
    monitor-exit v0

    .line 345
    goto :goto_5

    .line 346
    :catchall_1
    move-exception p0

    .line 347
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 348
    throw p0

    .line 349
    :cond_8
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingReq;

    .line 350
    .line 351
    if-eqz v0, :cond_9

    .line 352
    .line 353
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pingCommand:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 354
    .line 355
    goto :goto_3

    .line 356
    :cond_9
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 357
    .line 358
    if-eqz v0, :cond_a

    .line 359
    .line 360
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 361
    .line 362
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 363
    .line 364
    .line 365
    move-result v1

    .line 366
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 367
    .line 368
    .line 369
    move-result-object v1

    .line 370
    invoke-virtual {v0, v1, p1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 374
    .line 375
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendConfirmPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object v1

    .line 379
    move-object v2, p1

    .line 380
    check-cast v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 381
    .line 382
    invoke-interface {v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V

    .line 383
    .line 384
    .line 385
    goto :goto_3

    .line 386
    :cond_a
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    .line 387
    .line 388
    if-eqz v0, :cond_b

    .line 389
    .line 390
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 391
    .line 392
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getReceivedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 393
    .line 394
    .line 395
    move-result-object v1

    .line 396
    invoke-interface {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 397
    .line 398
    .line 399
    :cond_b
    :goto_3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 400
    .line 401
    monitor-enter v0

    .line 402
    :try_start_3
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 403
    .line 404
    if-nez v1, :cond_c

    .line 405
    .line 406
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 407
    .line 408
    invoke-virtual {v1, p2, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 409
    .line 410
    .line 411
    goto :goto_4

    .line 412
    :catchall_2
    move-exception p0

    .line 413
    goto :goto_6

    .line 414
    :cond_c
    :goto_4
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingFlows:Ljava/util/Vector;

    .line 415
    .line 416
    invoke-virtual {p2, p1}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 417
    .line 418
    .line 419
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 420
    .line 421
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 422
    .line 423
    .line 424
    monitor-exit v0

    .line 425
    :goto_5
    return-void

    .line 426
    :goto_6
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 427
    throw p0
.end method

.method public setCleanStart(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->cleanStart:Z

    .line 2
    .line 3
    return-void
.end method

.method public unPersistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 5

    .line 1
    const-string v0, "unPersistBufferedMessage"

    .line 2
    .line 3
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    .line 5
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 6
    .line 7
    const-string v3, "517"

    .line 8
    .line 9
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    invoke-interface {v1, v2, v0, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 21
    .line 22
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendBufferedPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-interface {v1, v2}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :catch_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 31
    .line 32
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    const-string v2, "518"

    .line 43
    .line 44
    invoke-interface {p0, v1, v0, v2, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public undo(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->queueLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    const-string v3, "undo"

    .line 9
    .line 10
    const-string v4, "618"

    .line 11
    .line 12
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 13
    .line 14
    .line 15
    move-result v5

    .line 16
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v5

    .line 20
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    invoke-virtual {v6}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    filled-new-array {v5, v6}, [Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    invoke-interface {v1, v2, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    const/4 v2, 0x1

    .line 48
    if-ne v1, v2, :cond_0

    .line 49
    .line 50
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 51
    .line 52
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-virtual {v1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto :goto_1

    .line 66
    :cond_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->outboundQoS2:Ljava/util/concurrent/ConcurrentHashMap;

    .line 67
    .line 68
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-virtual {v1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    :goto_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->pendingMessages:Ljava/util/Vector;

    .line 80
    .line 81
    invoke-virtual {v1, p1}, Ljava/util/Vector;->removeElement(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->persistence:Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;

    .line 85
    .line 86
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->getSendPersistenceKey(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    invoke-interface {v1, v2}, Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;->remove(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 94
    .line 95
    invoke-virtual {v1, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    if-lez v1, :cond_1

    .line 107
    .line 108
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    invoke-direct {p0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->releaseMessageId(I)V

    .line 113
    .line 114
    .line 115
    const/4 v1, 0x0

    .line 116
    invoke-virtual {p1, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->setMessageId(I)V

    .line 117
    .line 118
    .line 119
    :cond_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z

    .line 120
    .line 121
    .line 122
    monitor-exit v0

    .line 123
    return-void

    .line 124
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 125
    throw p0
.end method

.method public updateResult(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 0

    .line 1
    iget-object p0, p2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->update(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
