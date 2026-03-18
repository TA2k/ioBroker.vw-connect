.class Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;
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
    name = "ConnectBG"
.end annotation


# instance fields
.field clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field conPacket:Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

.field conToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private threadName:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;Ljava/util/concurrent/ExecutorService;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 7
    .line 8
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 9
    .line 10
    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conPacket:Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 11
    .line 12
    new-instance p2, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string p3, "MQTT Con: "

    .line 15
    .line 16
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->threadName:Ljava/lang/String;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public run()V
    .locals 8

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->threadName:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

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
    const-string v2, "connectBG:run"

    .line 21
    .line 22
    const-string v3, "220"

    .line 23
    .line 24
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 29
    .line 30
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$3(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->getOutstandingDelTokens()[Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    array-length v2, v0

    .line 39
    const/4 v3, 0x0

    .line 40
    :goto_0
    if-lt v3, v2, :cond_0

    .line 41
    .line 42
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 43
    .line 44
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$3(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 49
    .line 50
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conPacket:Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 51
    .line 52
    invoke-virtual {v0, v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 53
    .line 54
    .line 55
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 56
    .line 57
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$4(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)[Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 62
    .line 63
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$5(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    aget-object v0, v0, v2

    .line 68
    .line 69
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;->start()V

    .line 70
    .line 71
    .line 72
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 73
    .line 74
    new-instance v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 75
    .line 76
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 77
    .line 78
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$6(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 83
    .line 84
    invoke-static {v6}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$3(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 85
    .line 86
    .line 87
    move-result-object v6

    .line 88
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;->getInputStream()Ljava/io/InputStream;

    .line 89
    .line 90
    .line 91
    move-result-object v7

    .line 92
    invoke-direct {v3, v4, v5, v6, v7}, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/ClientState;Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;Ljava/io/InputStream;)V

    .line 93
    .line 94
    .line 95
    invoke-static {v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$7(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;)V

    .line 96
    .line 97
    .line 98
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 99
    .line 100
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$8(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    new-instance v3, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    const-string v4, "MQTT Rec: "

    .line 107
    .line 108
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 112
    .line 113
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-interface {v4}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v4

    .line 121
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 129
    .line 130
    invoke-static {v4}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    invoke-virtual {v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/CommsReceiver;->start(Ljava/lang/String;Ljava/util/concurrent/ExecutorService;)V

    .line 135
    .line 136
    .line 137
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 138
    .line 139
    new-instance v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 140
    .line 141
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 142
    .line 143
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$6(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 144
    .line 145
    .line 146
    move-result-object v5

    .line 147
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 148
    .line 149
    invoke-static {v6}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$3(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;

    .line 150
    .line 151
    .line 152
    move-result-object v6

    .line 153
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;->getOutputStream()Ljava/io/OutputStream;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    invoke-direct {v3, v4, v5, v6, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;-><init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/ClientState;Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;Ljava/io/OutputStream;)V

    .line 158
    .line 159
    .line 160
    invoke-static {v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$9(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;)V

    .line 161
    .line 162
    .line 163
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 164
    .line 165
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$10(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    new-instance v2, Ljava/lang/StringBuilder;

    .line 170
    .line 171
    const-string v3, "MQTT Snd: "

    .line 172
    .line 173
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 177
    .line 178
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    invoke-interface {v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 194
    .line 195
    invoke-static {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    invoke-virtual {v0, v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/CommsSender;->start(Ljava/lang/String;Ljava/util/concurrent/ExecutorService;)V

    .line 200
    .line 201
    .line 202
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 203
    .line 204
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$11(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    new-instance v2, Ljava/lang/StringBuilder;

    .line 209
    .line 210
    const-string v3, "MQTT Call: "

    .line 211
    .line 212
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 216
    .line 217
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 218
    .line 219
    .line 220
    move-result-object v3

    .line 221
    invoke-interface {v3}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v3

    .line 225
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 226
    .line 227
    .line 228
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 233
    .line 234
    invoke-static {v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 235
    .line 236
    .line 237
    move-result-object v3

    .line 238
    invoke-virtual {v0, v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->start(Ljava/lang/String;Ljava/util/concurrent/ExecutorService;)V

    .line 239
    .line 240
    .line 241
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 242
    .line 243
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conPacket:Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    .line 244
    .line 245
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 246
    .line 247
    invoke-virtual {v0, v2, v3}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 248
    .line 249
    .line 250
    move-object v0, v1

    .line 251
    goto :goto_3

    .line 252
    :catch_0
    move-exception v0

    .line 253
    move-object v7, v0

    .line 254
    goto :goto_1

    .line 255
    :catch_1
    move-exception v0

    .line 256
    move-object v7, v0

    .line 257
    goto :goto_2

    .line 258
    :cond_0
    aget-object v4, v0, v3

    .line 259
    .line 260
    iget-object v4, v4, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 261
    .line 262
    invoke-virtual {v4, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setException(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 263
    .line 264
    .line 265
    add-int/lit8 v3, v3, 0x1

    .line 266
    .line 267
    goto/16 :goto_0

    .line 268
    .line 269
    :goto_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 270
    .line 271
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$1(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$2()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v3

    .line 279
    const-string v5, "209"

    .line 280
    .line 281
    const/4 v6, 0x0

    .line 282
    const-string v4, "connectBG:run"

    .line 283
    .line 284
    invoke-interface/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 285
    .line 286
    .line 287
    invoke-static {v7}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(Ljava/lang/Throwable;)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    goto :goto_3

    .line 292
    :goto_2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 293
    .line 294
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$1(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$2()Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v3

    .line 302
    const-string v5, "212"

    .line 303
    .line 304
    const/4 v6, 0x0

    .line 305
    const-string v4, "connectBG:run"

    .line 306
    .line 307
    invoke-interface/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 308
    .line 309
    .line 310
    move-object v0, v7

    .line 311
    :goto_3
    if-eqz v0, :cond_1

    .line 312
    .line 313
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 314
    .line 315
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->conToken:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 316
    .line 317
    invoke-virtual {v2, p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 318
    .line 319
    .line 320
    :cond_1
    return-void
.end method

.method public start()V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Ljava/lang/Thread;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ConnectBG;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 19
    .line 20
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$0(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Ljava/util/concurrent/ExecutorService;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-interface {v0, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
