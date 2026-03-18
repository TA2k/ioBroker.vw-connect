.class Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "DisconnectBG"
.end annotation


# instance fields
.field disconnect:Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

.field quiesceTimeout:J

.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private threadName:Ljava/lang/String;

.field token:Lorg/eclipse/paho/mqttv5/client/MqttToken;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;JLorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/util/concurrent/ExecutorService;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->disconnect:Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 7
    .line 8
    iput-wide p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->quiesceTimeout:J

    .line 9
    .line 10
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->threadName:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 11
    .line 12
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$1(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$2()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const-string v2, "disconnectBG:run"

    .line 21
    .line 22
    const-string v3, "221"

    .line 23
    .line 24
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 28
    .line 29
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$6(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iget-wide v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->quiesceTimeout:J

    .line 34
    .line 35
    invoke-virtual {v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->quiesce(J)V

    .line 36
    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 40
    .line 41
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->disconnect:Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    .line 42
    .line 43
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 44
    .line 45
    invoke-virtual {v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 49
    .line 50
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    if-eqz v1, :cond_0

    .line 55
    .line 56
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 57
    .line 58
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_0

    .line 67
    .line 68
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 69
    .line 70
    iget-object v1, v1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 71
    .line 72
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitUntilSent()V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :catchall_0
    move-exception v1

    .line 77
    goto :goto_2

    .line 78
    :cond_0
    :goto_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 79
    .line 80
    iget-object v1, v1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 81
    .line 82
    invoke-virtual {v1, v0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 86
    .line 87
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    if-eqz v1, :cond_1

    .line 92
    .line 93
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 94
    .line 95
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-nez v1, :cond_2

    .line 104
    .line 105
    :cond_1
    :goto_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 106
    .line 107
    iget-object v1, v1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 108
    .line 109
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifyComplete()V

    .line 110
    .line 111
    .line 112
    :cond_2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 113
    .line 114
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 115
    .line 116
    invoke-virtual {v1, p0, v0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 117
    .line 118
    .line 119
    return-void

    .line 120
    :goto_2
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 121
    .line 122
    iget-object v2, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 123
    .line 124
    invoke-virtual {v2, v0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 125
    .line 126
    .line 127
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 128
    .line 129
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    if-eqz v2, :cond_3

    .line 134
    .line 135
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 136
    .line 137
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    if-nez v2, :cond_4

    .line 146
    .line 147
    :cond_3
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 148
    .line 149
    iget-object v2, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 150
    .line 151
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifyComplete()V

    .line 152
    .line 153
    .line 154
    :cond_4
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 155
    .line 156
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 157
    .line 158
    invoke-virtual {v2, p0, v0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 159
    .line 160
    .line 161
    throw v1

    .line 162
    :catch_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 163
    .line 164
    iget-object v1, v1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 165
    .line 166
    invoke-virtual {v1, v0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 167
    .line 168
    .line 169
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 170
    .line 171
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    if-eqz v1, :cond_1

    .line 176
    .line 177
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 178
    .line 179
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->isRunning()Z

    .line 184
    .line 185
    .line 186
    move-result v1

    .line 187
    if-nez v1, :cond_2

    .line 188
    .line 189
    goto :goto_1
.end method

.method public start()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MQTT Disc: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 9
    .line 10
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->threadName:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 28
    .line 29
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    new-instance v0, Ljava/lang/Thread;

    .line 36
    .line 37
    invoke-direct {v0, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$DisconnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 45
    .line 46
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-interface {v0, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 51
    .line 52
    .line 53
    return-void
.end method
