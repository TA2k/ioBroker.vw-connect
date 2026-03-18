.class public Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;
    }
.end annotation


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.CommsSender"


# instance fields
.field private clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

.field private current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

.field private final lifecycle:Ljava/lang/Object;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

.field private sendThread:Ljava/lang/Thread;

.field private senderFuture:Ljava/util/concurrent/Future;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/Future<",
            "*>;"
        }
    .end annotation
.end field

.field private target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

.field private threadName:Ljava/lang/String;

.field private tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/ClientState;Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;Ljava/io/OutputStream;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 15
    .line 16
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 17
    .line 18
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 19
    .line 20
    new-instance v0, Ljava/lang/Object;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->sendThread:Ljava/lang/Thread;

    .line 29
    .line 30
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 31
    .line 32
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 33
    .line 34
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 35
    .line 36
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

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
    invoke-direct {v0, p2, p4, v1}, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/MqttState;Ljava/io/OutputStream;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

    .line 50
    .line 51
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 52
    .line 53
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 54
    .line 55
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 56
    .line 57
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

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

.method private handleRunException(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Ljava/lang/Exception;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "handleRunException"

    .line 6
    .line 7
    const-string v3, "804"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    move-object v5, p2

    .line 11
    invoke-interface/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

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
    const/16 p2, 0x7d6d

    .line 21
    .line 22
    invoke-direct {p1, p2, v5}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILjava/lang/Throwable;)V

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
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 30
    .line 31
    monitor-enter p2

    .line 32
    :try_start_0
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 33
    .line 34
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 35
    .line 36
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 38
    .line 39
    const/4 p2, 0x0

    .line 40
    invoke-virtual {p0, p2, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    move-object p0, v0

    .line 46
    :try_start_1
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 47
    throw p0
.end method


# virtual methods
.method public isRunning()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 11
    .line 12
    if-ne p0, v2, :cond_0

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    monitor-exit v0

    .line 20
    return p0

    .line 21
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method

.method public run()V
    .locals 7

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->sendThread:Ljava/lang/Thread;

    .line 6
    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->threadName:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v0

    .line 15
    :try_start_0
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 16
    .line 17
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 18
    .line 19
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_7

    .line 20
    const/4 v0, 0x0

    .line 21
    :try_start_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 22
    .line 23
    monitor-enter v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    :try_start_2
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 25
    .line 26
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 27
    move-object v1, v0

    .line 28
    :goto_0
    :try_start_3
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 29
    .line 30
    if-ne v2, v3, :cond_5

    .line 31
    .line 32
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 33
    .line 34
    if-nez v2, :cond_0

    .line 35
    .line 36
    goto/16 :goto_6

    .line 37
    .line 38
    :cond_0
    :try_start_4
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 39
    .line 40
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->get()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    if-eqz v1, :cond_3

    .line 45
    .line 46
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 47
    .line 48
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 49
    .line 50
    const-string v4, "run"

    .line 51
    .line 52
    const-string v5, "802"

    .line 53
    .line 54
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v6

    .line 58
    filled-new-array {v6, v1}, [Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    invoke-interface {v2, v3, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    instance-of v2, v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 66
    .line 67
    if-eqz v2, :cond_1

    .line 68
    .line 69
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

    .line 70
    .line 71
    invoke-virtual {v2, v1}, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->write(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 72
    .line 73
    .line 74
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

    .line 75
    .line 76
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->flush()V

    .line 77
    .line 78
    .line 79
    goto :goto_5

    .line 80
    :catchall_0
    move-exception v1

    .line 81
    goto/16 :goto_7

    .line 82
    .line 83
    :catch_0
    move-exception v2

    .line 84
    goto :goto_3

    .line 85
    :catch_1
    move-exception v2

    .line 86
    goto :goto_4

    .line 87
    :cond_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->tokenStore:Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 88
    .line 89
    invoke-virtual {v2, v1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    if-eqz v2, :cond_4

    .line 94
    .line 95
    monitor-enter v2
    :try_end_4
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 96
    :try_start_5
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

    .line 97
    .line 98
    invoke-virtual {v3, v1}, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->write(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 99
    .line 100
    .line 101
    :try_start_6
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->out:Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;

    .line 102
    .line 103
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->flush()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_2
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :catchall_1
    move-exception v3

    .line 108
    goto :goto_2

    .line 109
    :catch_2
    move-exception v3

    .line 110
    :try_start_7
    instance-of v4, v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 111
    .line 112
    if-eqz v4, :cond_2

    .line 113
    .line 114
    :goto_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 115
    .line 116
    invoke-virtual {v3, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifySent(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 117
    .line 118
    .line 119
    monitor-exit v2

    .line 120
    goto :goto_5

    .line 121
    :cond_2
    throw v3

    .line 122
    :goto_2
    monitor-exit v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 123
    :try_start_8
    throw v3

    .line 124
    :cond_3
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 125
    .line 126
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 127
    .line 128
    const-string v4, "run"

    .line 129
    .line 130
    const-string v5, "803"

    .line 131
    .line 132
    invoke-interface {v2, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 136
    .line 137
    monitor-enter v2
    :try_end_8
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_8 .. :try_end_8} :catch_1
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 138
    :try_start_9
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 139
    .line 140
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 141
    .line 142
    monitor-exit v2

    .line 143
    goto :goto_5

    .line 144
    :catchall_2
    move-exception v3

    .line 145
    monitor-exit v2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 146
    :try_start_a
    throw v3
    :try_end_a
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_a .. :try_end_a} :catch_1
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_0
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 147
    :goto_3
    :try_start_b
    invoke-direct {p0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->handleRunException(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Ljava/lang/Exception;)V

    .line 148
    .line 149
    .line 150
    goto :goto_5

    .line 151
    :goto_4
    invoke-direct {p0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->handleRunException(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Ljava/lang/Exception;)V

    .line 152
    .line 153
    .line 154
    :cond_4
    :goto_5
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 155
    .line 156
    monitor-enter v2
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 157
    :try_start_c
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 158
    .line 159
    monitor-exit v2

    .line 160
    move-object v2, v3

    .line 161
    goto/16 :goto_0

    .line 162
    .line 163
    :catchall_3
    move-exception v1

    .line 164
    monitor-exit v2
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 165
    :try_start_d
    throw v1
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_0

    .line 166
    :cond_5
    :goto_6
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 167
    .line 168
    monitor-enter v1

    .line 169
    :try_start_e
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 170
    .line 171
    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 172
    .line 173
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->sendThread:Ljava/lang/Thread;

    .line 174
    .line 175
    monitor-exit v1
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    .line 176
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 177
    .line 178
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 179
    .line 180
    const-string v1, "run"

    .line 181
    .line 182
    const-string v2, "805"

    .line 183
    .line 184
    invoke-interface {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    return-void

    .line 188
    :catchall_4
    move-exception p0

    .line 189
    :try_start_f
    monitor-exit v1
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 190
    throw p0

    .line 191
    :catchall_5
    move-exception v2

    .line 192
    :try_start_10
    monitor-exit v1
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_5

    .line 193
    :try_start_11
    throw v2
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_0

    .line 194
    :goto_7
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 195
    .line 196
    monitor-enter v2

    .line 197
    :try_start_12
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 198
    .line 199
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 200
    .line 201
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->sendThread:Ljava/lang/Thread;

    .line 202
    .line 203
    monitor-exit v2
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_6

    .line 204
    throw v1

    .line 205
    :catchall_6
    move-exception p0

    .line 206
    :try_start_13
    monitor-exit v2
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_6

    .line 207
    throw p0

    .line 208
    :catchall_7
    move-exception p0

    .line 209
    :try_start_14
    monitor-exit v0
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_7

    .line 210
    throw p0
.end method

.method public start(Ljava/lang/String;Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->threadName:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter p1

    .line 6
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 7
    .line 8
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 9
    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 13
    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 17
    .line 18
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 19
    .line 20
    if-nez p2, :cond_0

    .line 21
    .line 22
    new-instance p2, Ljava/lang/Thread;

    .line 23
    .line 24
    invoke-direct {p2, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2}, Ljava/lang/Thread;->start()V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_2

    .line 33
    :cond_0
    invoke-interface {p2, p0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->senderFuture:Ljava/util/concurrent/Future;

    .line 38
    .line 39
    :cond_1
    :goto_0
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    :catch_0
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    if-eqz p1, :cond_2

    .line 45
    .line 46
    return-void

    .line 47
    :cond_2
    const-wide/16 p1, 0x64

    .line 48
    .line 49
    :try_start_1
    invoke-static {p1, p2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :goto_2
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 54
    throw p0
.end method

.method public stop()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->lifecycle:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->senderFuture:Ljava/util/concurrent/Future;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-interface {v1, v2}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    goto :goto_2

    .line 22
    :cond_1
    :goto_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 23
    .line 24
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 25
    .line 26
    const-string v3, "stop"

    .line 27
    .line 28
    const-string v4, "800"

    .line 29
    .line 30
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 40
    .line 41
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsSender$State;

    .line 42
    .line 43
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 44
    .line 45
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyQueueLock()V

    .line 46
    .line 47
    .line 48
    :cond_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-nez v0, :cond_3

    .line 54
    .line 55
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 56
    .line 57
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->CLASS_NAME:Ljava/lang/String;

    .line 58
    .line 59
    const-string v1, "stop"

    .line 60
    .line 61
    const-string v2, "801"

    .line 62
    .line 63
    invoke-interface {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    const-wide/16 v0, 0x64

    .line 68
    .line 69
    :try_start_1
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 70
    .line 71
    .line 72
    :catch_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 73
    .line 74
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyQueueLock()V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :goto_2
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 79
    throw p0
.end method
