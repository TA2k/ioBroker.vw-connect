.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final KEY:Ljava/lang/String; = "Disc"

.field private static final validProperties:[Ljava/lang/Byte;

.field private static final validReturnCodes:[I


# instance fields
.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private returnCode:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/16 v0, 0x1d

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x4

    .line 7
    aput v2, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x2

    .line 10
    const/16 v3, 0x80

    .line 11
    .line 12
    aput v3, v0, v1

    .line 13
    .line 14
    const/4 v1, 0x3

    .line 15
    const/16 v3, 0x81

    .line 16
    .line 17
    aput v3, v0, v1

    .line 18
    .line 19
    const/16 v1, 0x82

    .line 20
    .line 21
    aput v1, v0, v2

    .line 22
    .line 23
    const/4 v1, 0x5

    .line 24
    const/16 v2, 0x83

    .line 25
    .line 26
    aput v2, v0, v1

    .line 27
    .line 28
    const/4 v1, 0x6

    .line 29
    const/16 v2, 0x87

    .line 30
    .line 31
    aput v2, v0, v1

    .line 32
    .line 33
    const/4 v1, 0x7

    .line 34
    const/16 v2, 0x89

    .line 35
    .line 36
    aput v2, v0, v1

    .line 37
    .line 38
    const/16 v1, 0x8

    .line 39
    .line 40
    const/16 v2, 0x8b

    .line 41
    .line 42
    aput v2, v0, v1

    .line 43
    .line 44
    const/16 v1, 0x9

    .line 45
    .line 46
    const/16 v2, 0x8d

    .line 47
    .line 48
    aput v2, v0, v1

    .line 49
    .line 50
    const/16 v1, 0xa

    .line 51
    .line 52
    const/16 v2, 0x8e

    .line 53
    .line 54
    aput v2, v0, v1

    .line 55
    .line 56
    const/16 v1, 0xb

    .line 57
    .line 58
    const/16 v2, 0x8f

    .line 59
    .line 60
    aput v2, v0, v1

    .line 61
    .line 62
    const/16 v1, 0xc

    .line 63
    .line 64
    const/16 v2, 0x90

    .line 65
    .line 66
    aput v2, v0, v1

    .line 67
    .line 68
    const/16 v1, 0xd

    .line 69
    .line 70
    const/16 v2, 0x93

    .line 71
    .line 72
    aput v2, v0, v1

    .line 73
    .line 74
    const/16 v1, 0xe

    .line 75
    .line 76
    const/16 v2, 0x94

    .line 77
    .line 78
    aput v2, v0, v1

    .line 79
    .line 80
    const/16 v1, 0xf

    .line 81
    .line 82
    const/16 v2, 0x95

    .line 83
    .line 84
    aput v2, v0, v1

    .line 85
    .line 86
    const/16 v1, 0x10

    .line 87
    .line 88
    const/16 v2, 0x96

    .line 89
    .line 90
    aput v2, v0, v1

    .line 91
    .line 92
    const/16 v1, 0x97

    .line 93
    .line 94
    const/16 v2, 0x11

    .line 95
    .line 96
    aput v1, v0, v2

    .line 97
    .line 98
    const/16 v1, 0x12

    .line 99
    .line 100
    const/16 v3, 0x98

    .line 101
    .line 102
    aput v3, v0, v1

    .line 103
    .line 104
    const/16 v1, 0x13

    .line 105
    .line 106
    const/16 v3, 0x99

    .line 107
    .line 108
    aput v3, v0, v1

    .line 109
    .line 110
    const/16 v1, 0x14

    .line 111
    .line 112
    const/16 v3, 0x9a

    .line 113
    .line 114
    aput v3, v0, v1

    .line 115
    .line 116
    const/16 v1, 0x15

    .line 117
    .line 118
    const/16 v3, 0x9b

    .line 119
    .line 120
    aput v3, v0, v1

    .line 121
    .line 122
    const/16 v1, 0x16

    .line 123
    .line 124
    const/16 v3, 0x9c

    .line 125
    .line 126
    aput v3, v0, v1

    .line 127
    .line 128
    const/16 v1, 0x17

    .line 129
    .line 130
    const/16 v3, 0x9d

    .line 131
    .line 132
    aput v3, v0, v1

    .line 133
    .line 134
    const/16 v1, 0x18

    .line 135
    .line 136
    const/16 v3, 0x9e

    .line 137
    .line 138
    aput v3, v0, v1

    .line 139
    .line 140
    const/16 v1, 0x19

    .line 141
    .line 142
    const/16 v3, 0x9f

    .line 143
    .line 144
    aput v3, v0, v1

    .line 145
    .line 146
    const/16 v1, 0x1a

    .line 147
    .line 148
    const/16 v3, 0xa0

    .line 149
    .line 150
    aput v3, v0, v1

    .line 151
    .line 152
    const/16 v1, 0x1b

    .line 153
    .line 154
    const/16 v3, 0xa1

    .line 155
    .line 156
    aput v3, v0, v1

    .line 157
    .line 158
    const/16 v1, 0xa2

    .line 159
    .line 160
    const/16 v3, 0x1c

    .line 161
    .line 162
    aput v1, v0, v3

    .line 163
    .line 164
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->validReturnCodes:[I

    .line 165
    .line 166
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    const/16 v2, 0x1f

    .line 175
    .line 176
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    const/16 v3, 0x26

    .line 181
    .line 182
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    filled-new-array {v0, v1, v2, v3}, [Ljava/lang/Byte;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->validProperties:[Ljava/lang/Byte;

    .line 191
    .line 192
    return-void
.end method

.method public constructor <init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/16 v0, 0xe

    .line 13
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    const/4 v0, 0x0

    .line 14
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    .line 15
    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->validReturnCodes:[I

    invoke-virtual {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 16
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    if-eqz p2, :cond_0

    .line 17
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 18
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 19
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
.end method

.method public constructor <init>([B)V
    .locals 6

    const/16 v0, 0xe

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    .line 3
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 4
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 5
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;

    invoke-direct {v1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;-><init>(Ljava/io/InputStream;)V

    .line 6
    new-instance v0, Ljava/io/DataInputStream;

    invoke-direct {v0, v1}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 7
    array-length v2, p1

    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result v3

    sub-int/2addr v2, v3

    const/4 v3, 0x1

    if-lt v2, v3, :cond_0

    .line 8
    invoke-virtual {v0}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result v2

    iput v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    .line 9
    sget-object v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->validReturnCodes:[I

    invoke-virtual {p0, v2, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 10
    :cond_0
    array-length p1, p1

    int-to-long v2, p1

    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result p1

    int-to-long v4, p1

    sub-long/2addr v2, v4

    const-wide/16 v4, 0x2

    cmp-long p1, v2, v4

    if-ltz p1, :cond_1

    .line 11
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 12
    :cond_1
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-void
.end method


# virtual methods
.method public getMessageInfo()B
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReturnCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    .line 2
    .line 3
    return p0
.end method

.method public getVariableHeader()[B
    .locals 3

    .line 1
    :try_start_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/io/DataOutputStream;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 9
    .line 10
    .line 11
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    .line 12
    .line 13
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 17
    .line 18
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    array-length v2, p0

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 29
    .line 30
    .line 31
    :cond_0
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 32
    .line 33
    .line 34
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    return-object p0

    .line 36
    :catch_0
    move-exception p0

    .line 37
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 38
    .line 39
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 40
    .line 41
    .line 42
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttDisconnect [returnCode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->returnCode:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", properties="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "]"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
