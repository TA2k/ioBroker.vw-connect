.class public Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;
.super Ljava/io/InputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.wire.MqttInputStream"


# instance fields
.field private bais:Ljava/io/ByteArrayOutputStream;

.field private clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

.field private in:Ljava/io/DataInputStream;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private packet:[B

.field private packetLen:I

.field private remLen:I


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/MqttState;Ljava/io/InputStream;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/io/InputStream;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 15
    .line 16
    new-instance p1, Ljava/io/DataInputStream;

    .line 17
    .line 18
    invoke-direct {p1, p2}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 22
    .line 23
    new-instance p1, Ljava/io/ByteArrayOutputStream;

    .line 24
    .line 25
    invoke-direct {p1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 29
    .line 30
    const/4 p1, -0x1

    .line 31
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 32
    .line 33
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 34
    .line 35
    invoke-interface {p0, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method private readFully()V
    .locals 7

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packetLen:I

    .line 8
    .line 9
    add-int/2addr v0, v1

    .line 10
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 11
    .line 12
    sub-int/2addr v2, v1

    .line 13
    if-ltz v2, :cond_2

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    :goto_0
    if-lt v1, v2, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    :try_start_0
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 20
    .line 21
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packet:[B

    .line 22
    .line 23
    add-int v5, v0, v1

    .line 24
    .line 25
    sub-int v6, v2, v1

    .line 26
    .line 27
    invoke-virtual {v3, v4, v5, v6}, Ljava/io/DataInputStream;->read([BII)I

    .line 28
    .line 29
    .line 30
    move-result v3
    :try_end_0
    .catch Ljava/net/SocketTimeoutException; {:try_start_0 .. :try_end_0} :catch_0

    .line 31
    if-ltz v3, :cond_1

    .line 32
    .line 33
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 34
    .line 35
    invoke-interface {v4, v3}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->notifyReceivedBytes(I)V

    .line 36
    .line 37
    .line 38
    add-int/2addr v1, v3

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    new-instance p0, Ljava/io/EOFException;

    .line 41
    .line 42
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :catch_0
    move-exception v0

    .line 47
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packetLen:I

    .line 48
    .line 49
    add-int/2addr v2, v1

    .line 50
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packetLen:I

    .line 51
    .line 52
    throw v0

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 54
    .line 55
    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    .line 56
    .line 57
    .line 58
    throw p0
.end method


# virtual methods
.method public available()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/InputStream;->available()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public read()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/InputStream;->read()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public readMqttWireMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    if-gez v1, :cond_3

    .line 6
    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->reset()V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readByte()B

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 19
    .line 20
    const/4 v4, 0x1

    .line 21
    invoke-interface {v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->notifyReceivedBytes(I)V

    .line 22
    .line 23
    .line 24
    ushr-int/lit8 v3, v1, 0x4

    .line 25
    .line 26
    const/16 v5, 0xf

    .line 27
    .line 28
    and-int/2addr v3, v5

    .line 29
    int-to-byte v3, v3

    .line 30
    if-lt v3, v4, :cond_2

    .line 31
    .line 32
    if-gt v3, v5, :cond_2

    .line 33
    .line 34
    and-int/lit8 v4, v1, 0xf

    .line 35
    .line 36
    int-to-byte v4, v4

    .line 37
    invoke-static {v3, v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReservedBits(BB)V

    .line 38
    .line 39
    .line 40
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->in:Ljava/io/DataInputStream;

    .line 41
    .line 42
    invoke-static {v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readVariableByteInteger(Ljava/io/DataInputStream;)Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->getValue()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    iput v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 51
    .line 52
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 53
    .line 54
    invoke-virtual {v3, v1}, Ljava/io/ByteArrayOutputStream;->write(I)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 58
    .line 59
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 60
    .line 61
    invoke-static {v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->encodeVariableByteInteger(I)[B

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-virtual {v1, v3}, Ljava/io/OutputStream;->write([B)V

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 69
    .line 70
    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->size()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 75
    .line 76
    add-int/2addr v1, v3

    .line 77
    new-array v1, v1, [B

    .line 78
    .line 79
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packet:[B

    .line 80
    .line 81
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 82
    .line 83
    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->getIncomingMaximumPacketSize()Ljava/lang/Long;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    if-eqz v1, :cond_1

    .line 88
    .line 89
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->size()I

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    iget v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 96
    .line 97
    add-int/2addr v1, v3

    .line 98
    int-to-long v3, v1

    .line 99
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 100
    .line 101
    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->getIncomingMaximumPacketSize()Ljava/lang/Long;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 106
    .line 107
    .line 108
    move-result-wide v5

    .line 109
    cmp-long v1, v3, v5

    .line 110
    .line 111
    if-gtz v1, :cond_0

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_0
    const p0, 0xc739

    .line 115
    .line 116
    .line 117
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    throw p0

    .line 122
    :cond_1
    :goto_0
    iput v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packetLen:I

    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_2
    const/16 p0, 0x7d6c

    .line 126
    .line 127
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    throw p0

    .line 132
    :cond_3
    :goto_1
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 133
    .line 134
    if-ltz v1, :cond_4

    .line 135
    .line 136
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->readFully()V

    .line 137
    .line 138
    .line 139
    const/4 v1, -0x1

    .line 140
    iput v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->remLen:I

    .line 141
    .line 142
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->bais:Ljava/io/ByteArrayOutputStream;

    .line 143
    .line 144
    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packet:[B

    .line 149
    .line 150
    array-length v4, v1

    .line 151
    invoke-static {v1, v2, v3, v2, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 152
    .line 153
    .line 154
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->packet:[B

    .line 155
    .line 156
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->createWireMessage([B)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 161
    .line 162
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/wire/MqttInputStream;->CLASS_NAME:Ljava/lang/String;

    .line 163
    .line 164
    const-string v2, "readMqttWireMessage"

    .line 165
    .line 166
    const-string v3, "530"

    .line 167
    .line 168
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v4

    .line 172
    invoke-interface {p0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/net/SocketTimeoutException; {:try_start_0 .. :try_end_0} :catch_0

    .line 173
    .line 174
    .line 175
    :catch_0
    :cond_4
    return-object v0
.end method
