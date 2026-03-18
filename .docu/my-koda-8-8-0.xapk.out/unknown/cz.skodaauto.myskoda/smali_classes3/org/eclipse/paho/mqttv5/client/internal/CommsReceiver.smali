.class public Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;
    }
.end annotation


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.CommsReceiver"


# instance fields
.field private clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

.field private current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

.field private in:Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;

.field private final lifecycle:Ljava/lang/Object;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private recThread:Ljava/lang/Thread;

.field private receiverFuture:Ljava/util/concurrent/Future;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/Future<",
            "*>;"
        }
    .end annotation
.end field

.field private target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

.field private threadName:Ljava/lang/String;

.field private tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/ClientState;Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;Ljava/io/InputStream;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 15
    .line 16
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 17
    .line 18
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 19
    .line 20
    new-instance v0, Ljava/lang/Object;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 29
    .line 30
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 31
    .line 32
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 33
    .line 34
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->recThread:Ljava/lang/Thread;

    .line 35
    .line 36
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;

    .line 37
    .line 38
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-direct {v0, p2, p4, v1}, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/MqttState;Ljava/io/InputStream;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->in:Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;

    .line 50
    .line 51
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 52
    .line 53
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 54
    .line 55
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 56
    .line 57
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 58
    .line 59
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-interface {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public isReceiving()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RECEIVING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 7
    .line 8
    if-ne p0, v1, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    monitor-exit v0

    .line 14
    return p0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method

.method public isRunning()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RECEIVING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 11
    .line 12
    if-ne v1, v3, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    goto :goto_2

    .line 17
    :cond_0
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 18
    .line 19
    if-ne p0, v2, :cond_1

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    :goto_1
    monitor-exit v0

    .line 25
    return p0

    .line 26
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method

.method public run()V
    .locals 9

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->recThread:Ljava/lang/Thread;

    .line 6
    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->threadName:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v1

    .line 15
    :try_start_0
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 16
    .line 17
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 18
    .line 19
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_f

    .line 20
    :try_start_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 23
    :try_start_2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 24
    .line 25
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_d

    .line 26
    const/4 v1, 0x0

    .line 27
    move-object v2, v1

    .line 28
    :goto_0
    :try_start_3
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 29
    .line 30
    if-ne v0, v3, :cond_9

    .line 31
    .line 32
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->in:Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_4

    .line 33
    .line 34
    if-nez v0, :cond_0

    .line 35
    .line 36
    goto/16 :goto_8

    .line 37
    .line 38
    :cond_0
    :try_start_4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 39
    .line 40
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 41
    .line 42
    const-string v5, "run"

    .line 43
    .line 44
    const-string v6, "852"

    .line 45
    .line 46
    invoke-interface {v0, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->in:Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;

    .line 50
    .line 51
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->available()I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-lez v0, :cond_1

    .line 56
    .line 57
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 58
    .line 59
    monitor-enter v5
    :try_end_4
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 60
    :try_start_5
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RECEIVING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 61
    .line 62
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 63
    .line 64
    monitor-exit v5

    .line 65
    goto :goto_1

    .line 66
    :catchall_0
    move-exception v0

    .line 67
    monitor-exit v5
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 68
    :try_start_6
    throw v0

    .line 69
    :catchall_1
    move-exception v0

    .line 70
    goto/16 :goto_7

    .line 71
    .line 72
    :catch_0
    move-exception v0

    .line 73
    goto/16 :goto_3

    .line 74
    .line 75
    :catch_1
    move-exception v0

    .line 76
    move-object v8, v0

    .line 77
    goto/16 :goto_5

    .line 78
    .line 79
    :cond_1
    :goto_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->in:Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;

    .line 80
    .line 81
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->readMqttWireMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 86
    .line 87
    monitor-enter v5
    :try_end_6
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 88
    :try_start_7
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 89
    .line 90
    monitor-exit v5
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 91
    :try_start_8
    instance-of v5, v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 92
    .line 93
    if-eqz v5, :cond_3

    .line 94
    .line 95
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 96
    .line 97
    invoke-virtual {v5, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    if-eqz v2, :cond_2

    .line 102
    .line 103
    monitor-enter v2
    :try_end_8
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_8 .. :try_end_8} :catch_1
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 104
    :try_start_9
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 105
    .line 106
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 107
    .line 108
    invoke-virtual {v4, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyReceivedAck(Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;)V

    .line 109
    .line 110
    .line 111
    monitor-exit v2

    .line 112
    goto :goto_2

    .line 113
    :catchall_2
    move-exception v0

    .line 114
    monitor-exit v2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 115
    :try_start_a
    throw v0

    .line 116
    :cond_2
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 117
    .line 118
    const-string v6, "run"

    .line 119
    .line 120
    const-string v7, "857"

    .line 121
    .line 122
    invoke-interface {v5, v4, v6, v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 126
    .line 127
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 128
    .line 129
    invoke-virtual {v4, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->handleOrphanedAcks(Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;)V

    .line 130
    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_3
    if-eqz v0, :cond_4

    .line 134
    .line 135
    instance-of v4, v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 136
    .line 137
    if-eqz v4, :cond_4

    .line 138
    .line 139
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 140
    .line 141
    new-instance v5, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 142
    .line 143
    move-object v6, v0

    .line 144
    check-cast v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 145
    .line 146
    const/16 v7, 0x7dcc

    .line 147
    .line 148
    invoke-direct {v5, v7, v6}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 149
    .line 150
    .line 151
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 152
    .line 153
    invoke-virtual {v4, v1, v5, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 154
    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_4
    if-eqz v0, :cond_5

    .line 158
    .line 159
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 160
    .line 161
    invoke-virtual {v4, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyReceivedMsg(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 166
    .line 167
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    if-nez v0, :cond_7

    .line 172
    .line 173
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 174
    .line 175
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnecting()Z

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    if-eqz v0, :cond_6

    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_6
    new-instance v0, Ljava/io/IOException;

    .line 183
    .line 184
    const-string v3, "Connection is lost."

    .line 185
    .line 186
    invoke-direct {v0, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    throw v0
    :try_end_a
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_a .. :try_end_a} :catch_1
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_0
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 190
    :cond_7
    :goto_2
    :try_start_b
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 191
    .line 192
    monitor-enter v4
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 193
    :try_start_c
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 194
    .line 195
    monitor-exit v4

    .line 196
    goto :goto_6

    .line 197
    :catchall_3
    move-exception v0

    .line 198
    monitor-exit v4
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 199
    :try_start_d
    throw v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 200
    :catchall_4
    move-exception v0

    .line 201
    goto/16 :goto_9

    .line 202
    .line 203
    :catchall_5
    move-exception v0

    .line 204
    :try_start_e
    monitor-exit v5
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_5

    .line 205
    :try_start_f
    throw v0
    :try_end_f
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_f .. :try_end_f} :catch_1
    .catch Ljava/io/IOException; {:try_start_f .. :try_end_f} :catch_0
    .catchall {:try_start_f .. :try_end_f} :catchall_1

    .line 206
    :goto_3
    :try_start_10
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 207
    .line 208
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 209
    .line 210
    const-string v5, "run"

    .line 211
    .line 212
    const-string v6, "853"

    .line 213
    .line 214
    invoke-interface {v3, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 218
    .line 219
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 220
    .line 221
    if-eq v3, v4, :cond_8

    .line 222
    .line 223
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 224
    .line 225
    monitor-enter v3
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_1

    .line 226
    :try_start_11
    iput-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 227
    .line 228
    monitor-exit v3
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_6

    .line 229
    :try_start_12
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 230
    .line 231
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isDisconnecting()Z

    .line 232
    .line 233
    .line 234
    move-result v3

    .line 235
    if-nez v3, :cond_8

    .line 236
    .line 237
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 238
    .line 239
    new-instance v4, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 240
    .line 241
    const/16 v5, 0x7d6d

    .line 242
    .line 243
    invoke-direct {v4, v5, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILjava/lang/Throwable;)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v3, v2, v4, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_1

    .line 247
    .line 248
    .line 249
    goto :goto_4

    .line 250
    :catchall_6
    move-exception v0

    .line 251
    :try_start_13
    monitor-exit v3
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_6

    .line 252
    :try_start_14
    throw v0
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_1

    .line 253
    :cond_8
    :goto_4
    :try_start_15
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 254
    .line 255
    monitor-enter v3
    :try_end_15
    .catchall {:try_start_15 .. :try_end_15} :catchall_4

    .line 256
    :try_start_16
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 257
    .line 258
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 259
    .line 260
    monitor-exit v3

    .line 261
    goto :goto_6

    .line 262
    :catchall_7
    move-exception v0

    .line 263
    monitor-exit v3
    :try_end_16
    .catchall {:try_start_16 .. :try_end_16} :catchall_7

    .line 264
    :try_start_17
    throw v0
    :try_end_17
    .catchall {:try_start_17 .. :try_end_17} :catchall_4

    .line 265
    :goto_5
    :try_start_18
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 266
    .line 267
    sget-object v4, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 268
    .line 269
    const-string v5, "run"

    .line 270
    .line 271
    const-string v6, "856"

    .line 272
    .line 273
    const/4 v7, 0x0

    .line 274
    invoke-interface/range {v3 .. v8}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 275
    .line 276
    .line 277
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 278
    .line 279
    monitor-enter v3
    :try_end_18
    .catchall {:try_start_18 .. :try_end_18} :catchall_1

    .line 280
    :try_start_19
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 281
    .line 282
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 283
    .line 284
    monitor-exit v3
    :try_end_19
    .catchall {:try_start_19 .. :try_end_19} :catchall_a

    .line 285
    :try_start_1a
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 286
    .line 287
    invoke-virtual {v0, v2, v8, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V
    :try_end_1a
    .catchall {:try_start_1a .. :try_end_1a} :catchall_1

    .line 288
    .line 289
    .line 290
    :try_start_1b
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 291
    .line 292
    monitor-enter v3
    :try_end_1b
    .catchall {:try_start_1b .. :try_end_1b} :catchall_4

    .line 293
    :try_start_1c
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 294
    .line 295
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 296
    .line 297
    monitor-exit v3
    :try_end_1c
    .catchall {:try_start_1c .. :try_end_1c} :catchall_9

    .line 298
    :goto_6
    :try_start_1d
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 299
    .line 300
    monitor-enter v3
    :try_end_1d
    .catchall {:try_start_1d .. :try_end_1d} :catchall_4

    .line 301
    :try_start_1e
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 302
    .line 303
    monitor-exit v3

    .line 304
    goto/16 :goto_0

    .line 305
    .line 306
    :catchall_8
    move-exception v0

    .line 307
    monitor-exit v3
    :try_end_1e
    .catchall {:try_start_1e .. :try_end_1e} :catchall_8

    .line 308
    :try_start_1f
    throw v0
    :try_end_1f
    .catchall {:try_start_1f .. :try_end_1f} :catchall_4

    .line 309
    :catchall_9
    move-exception v0

    .line 310
    :try_start_20
    monitor-exit v3
    :try_end_20
    .catchall {:try_start_20 .. :try_end_20} :catchall_9

    .line 311
    :try_start_21
    throw v0
    :try_end_21
    .catchall {:try_start_21 .. :try_end_21} :catchall_4

    .line 312
    :catchall_a
    move-exception v0

    .line 313
    :try_start_22
    monitor-exit v3
    :try_end_22
    .catchall {:try_start_22 .. :try_end_22} :catchall_a

    .line 314
    :try_start_23
    throw v0
    :try_end_23
    .catchall {:try_start_23 .. :try_end_23} :catchall_1

    .line 315
    :goto_7
    :try_start_24
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 316
    .line 317
    monitor-enter v1
    :try_end_24
    .catchall {:try_start_24 .. :try_end_24} :catchall_4

    .line 318
    :try_start_25
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 319
    .line 320
    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 321
    .line 322
    monitor-exit v1
    :try_end_25
    .catchall {:try_start_25 .. :try_end_25} :catchall_b

    .line 323
    :try_start_26
    throw v0
    :try_end_26
    .catchall {:try_start_26 .. :try_end_26} :catchall_4

    .line 324
    :catchall_b
    move-exception v0

    .line 325
    :try_start_27
    monitor-exit v1
    :try_end_27
    .catchall {:try_start_27 .. :try_end_27} :catchall_b

    .line 326
    :try_start_28
    throw v0
    :try_end_28
    .catchall {:try_start_28 .. :try_end_28} :catchall_4

    .line 327
    :cond_9
    :goto_8
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 328
    .line 329
    monitor-enter v2

    .line 330
    :try_start_29
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 331
    .line 332
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 333
    .line 334
    monitor-exit v2
    :try_end_29
    .catchall {:try_start_29 .. :try_end_29} :catchall_c

    .line 335
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->recThread:Ljava/lang/Thread;

    .line 336
    .line 337
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 338
    .line 339
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 340
    .line 341
    const-string v1, "run"

    .line 342
    .line 343
    const-string v2, "854"

    .line 344
    .line 345
    invoke-interface {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 346
    .line 347
    .line 348
    return-void

    .line 349
    :catchall_c
    move-exception v0

    .line 350
    move-object p0, v0

    .line 351
    :try_start_2a
    monitor-exit v2
    :try_end_2a
    .catchall {:try_start_2a .. :try_end_2a} :catchall_c

    .line 352
    throw p0

    .line 353
    :catchall_d
    move-exception v0

    .line 354
    :try_start_2b
    monitor-exit v1
    :try_end_2b
    .catchall {:try_start_2b .. :try_end_2b} :catchall_d

    .line 355
    :try_start_2c
    throw v0
    :try_end_2c
    .catchall {:try_start_2c .. :try_end_2c} :catchall_4

    .line 356
    :goto_9
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 357
    .line 358
    monitor-enter v2

    .line 359
    :try_start_2d
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 360
    .line 361
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 362
    .line 363
    monitor-exit v2
    :try_end_2d
    .catchall {:try_start_2d .. :try_end_2d} :catchall_e

    .line 364
    throw v0

    .line 365
    :catchall_e
    move-exception v0

    .line 366
    move-object p0, v0

    .line 367
    :try_start_2e
    monitor-exit v2
    :try_end_2e
    .catchall {:try_start_2e .. :try_end_2e} :catchall_e

    .line 368
    throw p0

    .line 369
    :catchall_f
    move-exception v0

    .line 370
    move-object p0, v0

    .line 371
    :try_start_2f
    monitor-exit v1
    :try_end_2f
    .catchall {:try_start_2f .. :try_end_2f} :catchall_f

    .line 372
    throw p0
.end method

.method public start(Ljava/lang/String;Ljava/util/concurrent/ExecutorService;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->threadName:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    .line 5
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "start"

    .line 8
    .line 9
    const-string v2, "855"

    .line 10
    .line 11
    invoke-interface {p1, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter p1

    .line 17
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 18
    .line 19
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 20
    .line 21
    if-ne v0, v1, :cond_1

    .line 22
    .line 23
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 24
    .line 25
    if-ne v0, v1, :cond_1

    .line 26
    .line 27
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 28
    .line 29
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 30
    .line 31
    if-nez p2, :cond_0

    .line 32
    .line 33
    new-instance p2, Ljava/lang/Thread;

    .line 34
    .line 35
    invoke-direct {p2, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Thread;->start()V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    goto :goto_2

    .line 44
    :cond_0
    invoke-interface {p2, p0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->receiverFuture:Ljava/util/concurrent/Future;

    .line 49
    .line 50
    :cond_1
    :goto_0
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    :catch_0
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->isRunning()Z

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    return-void

    .line 58
    :cond_2
    const-wide/16 p1, 0x64

    .line 59
    .line 60
    :try_start_1
    invoke-static {p1, p2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :goto_2
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 65
    throw p0
.end method

.method public stop()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->receiverFuture:Ljava/util/concurrent/Future;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-interface {v1, v2}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_2

    .line 15
    :cond_0
    :goto_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 16
    .line 17
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 18
    .line 19
    const-string v3, "stop"

    .line 20
    .line 21
    const-string v4, "850"

    .line 22
    .line 23
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->isRunning()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 33
    .line 34
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver$State;

    .line 35
    .line 36
    :cond_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    :catch_0
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->isRunning()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_2

    .line 42
    .line 43
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 44
    .line 45
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->CLASS_NAME:Ljava/lang/String;

    .line 46
    .line 47
    const-string v1, "stop"

    .line 48
    .line 49
    const-string v2, "851"

    .line 50
    .line 51
    invoke-interface {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    const-wide/16 v0, 0x64

    .line 56
    .line 57
    :try_start_1
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :goto_2
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 62
    throw p0
.end method
