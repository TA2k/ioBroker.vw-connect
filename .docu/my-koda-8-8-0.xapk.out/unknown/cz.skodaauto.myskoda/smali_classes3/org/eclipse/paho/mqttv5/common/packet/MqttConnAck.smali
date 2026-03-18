.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final KEY:Ljava/lang/String; = "Con"

.field private static final validProperties:[Ljava/lang/Byte;

.field private static final validReturnCodes:[I


# instance fields
.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private sessionPresent:Z


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    const/16 v0, 0x14

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    const/16 v2, 0x80

    .line 7
    .line 8
    aput v2, v0, v1

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    const/16 v2, 0x81

    .line 12
    .line 13
    aput v2, v0, v1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    const/16 v2, 0x82

    .line 17
    .line 18
    aput v2, v0, v1

    .line 19
    .line 20
    const/4 v1, 0x4

    .line 21
    const/16 v2, 0x83

    .line 22
    .line 23
    aput v2, v0, v1

    .line 24
    .line 25
    const/4 v1, 0x5

    .line 26
    const/16 v2, 0x84

    .line 27
    .line 28
    aput v2, v0, v1

    .line 29
    .line 30
    const/4 v1, 0x6

    .line 31
    const/16 v2, 0x85

    .line 32
    .line 33
    aput v2, v0, v1

    .line 34
    .line 35
    const/4 v1, 0x7

    .line 36
    const/16 v2, 0x86

    .line 37
    .line 38
    aput v2, v0, v1

    .line 39
    .line 40
    const/16 v1, 0x8

    .line 41
    .line 42
    const/16 v2, 0x87

    .line 43
    .line 44
    aput v2, v0, v1

    .line 45
    .line 46
    const/16 v1, 0x9

    .line 47
    .line 48
    const/16 v2, 0x88

    .line 49
    .line 50
    aput v2, v0, v1

    .line 51
    .line 52
    const/16 v1, 0xa

    .line 53
    .line 54
    const/16 v2, 0x89

    .line 55
    .line 56
    aput v2, v0, v1

    .line 57
    .line 58
    const/16 v1, 0xb

    .line 59
    .line 60
    const/16 v2, 0x8a

    .line 61
    .line 62
    aput v2, v0, v1

    .line 63
    .line 64
    const/16 v1, 0xc

    .line 65
    .line 66
    const/16 v2, 0x8c

    .line 67
    .line 68
    aput v2, v0, v1

    .line 69
    .line 70
    const/16 v1, 0xd

    .line 71
    .line 72
    const/16 v2, 0x90

    .line 73
    .line 74
    aput v2, v0, v1

    .line 75
    .line 76
    const/16 v1, 0xe

    .line 77
    .line 78
    const/16 v2, 0x95

    .line 79
    .line 80
    aput v2, v0, v1

    .line 81
    .line 82
    const/16 v1, 0xf

    .line 83
    .line 84
    const/16 v2, 0x97

    .line 85
    .line 86
    aput v2, v0, v1

    .line 87
    .line 88
    const/16 v1, 0x10

    .line 89
    .line 90
    const/16 v2, 0x9a

    .line 91
    .line 92
    aput v2, v0, v1

    .line 93
    .line 94
    const/16 v1, 0x9c

    .line 95
    .line 96
    const/16 v2, 0x11

    .line 97
    .line 98
    aput v1, v0, v2

    .line 99
    .line 100
    const/16 v1, 0x9d

    .line 101
    .line 102
    const/16 v3, 0x12

    .line 103
    .line 104
    aput v1, v0, v3

    .line 105
    .line 106
    const/16 v1, 0x9f

    .line 107
    .line 108
    const/16 v4, 0x13

    .line 109
    .line 110
    aput v1, v0, v4

    .line 111
    .line 112
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validReturnCodes:[I

    .line 113
    .line 114
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    const/16 v0, 0x21

    .line 119
    .line 120
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    const/16 v0, 0x24

    .line 125
    .line 126
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 127
    .line 128
    .line 129
    move-result-object v7

    .line 130
    const/16 v0, 0x25

    .line 131
    .line 132
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 133
    .line 134
    .line 135
    move-result-object v8

    .line 136
    const/16 v0, 0x27

    .line 137
    .line 138
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 139
    .line 140
    .line 141
    move-result-object v9

    .line 142
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 143
    .line 144
    .line 145
    move-result-object v10

    .line 146
    const/16 v0, 0x22

    .line 147
    .line 148
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 149
    .line 150
    .line 151
    move-result-object v11

    .line 152
    const/16 v0, 0x28

    .line 153
    .line 154
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 155
    .line 156
    .line 157
    move-result-object v12

    .line 158
    const/16 v0, 0x29

    .line 159
    .line 160
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 161
    .line 162
    .line 163
    move-result-object v13

    .line 164
    const/16 v0, 0x2a

    .line 165
    .line 166
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 167
    .line 168
    .line 169
    move-result-object v14

    .line 170
    invoke-static {v4}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 171
    .line 172
    .line 173
    move-result-object v15

    .line 174
    const/16 v0, 0x1a

    .line 175
    .line 176
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 177
    .line 178
    .line 179
    move-result-object v16

    .line 180
    const/16 v0, 0x1c

    .line 181
    .line 182
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 183
    .line 184
    .line 185
    move-result-object v17

    .line 186
    const/16 v0, 0x15

    .line 187
    .line 188
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 189
    .line 190
    .line 191
    move-result-object v18

    .line 192
    const/16 v0, 0x16

    .line 193
    .line 194
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 195
    .line 196
    .line 197
    move-result-object v19

    .line 198
    const/16 v0, 0x1f

    .line 199
    .line 200
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 201
    .line 202
    .line 203
    move-result-object v20

    .line 204
    const/16 v0, 0x26

    .line 205
    .line 206
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 207
    .line 208
    .line 209
    move-result-object v21

    .line 210
    filled-new-array/range {v5 .. v21}, [Ljava/lang/Byte;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validProperties:[Ljava/lang/Byte;

    .line 215
    .line 216
    return-void
.end method

.method public constructor <init>(ZILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/4 v0, 0x2

    .line 10
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    if-eqz p3, :cond_0

    .line 11
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 12
    :cond_0
    new-instance p3, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 13
    :goto_0
    iget-object p3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p3, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    .line 14
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->sessionPresent:Z

    .line 15
    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validReturnCodes:[I

    invoke-virtual {p0, p2, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 16
    iput p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    return-void
.end method

.method public constructor <init>([B)V
    .locals 2

    const/4 v0, 0x2

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 3
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 4
    new-instance p1, Ljava/io/DataInputStream;

    invoke-direct {p1, v0}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 5
    invoke-virtual {p1}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result v0

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->sessionPresent:Z

    .line 6
    invoke-virtual {p1}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result v0

    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 7
    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validReturnCodes:[I

    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 8
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 9
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V

    return-void
.end method

.method public static getValidreturncodes()[I
    .locals 1

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->validReturnCodes:[I

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Con"

    .line 2
    .line 3
    return-object p0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReturnCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 2
    .line 3
    return p0
.end method

.method public getSessionPresent()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->sessionPresent:Z

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
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->sessionPresent:Z

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    int-to-byte v2, v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v2, 0x0

    .line 19
    :goto_0
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 20
    .line 21
    .line 22
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 23
    .line 24
    int-to-byte v2, v2

    .line 25
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 29
    .line 30
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 41
    .line 42
    .line 43
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    return-object p0

    .line 45
    :catch_0
    move-exception p0

    .line 46
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 47
    .line 48
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 49
    .line 50
    .line 51
    throw v0
.end method

.method public isMessageIdRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public setReturnCode(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 2
    .line 3
    return-void
.end method

.method public setSessionPresent(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->sessionPresent:Z

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttConnAck [returnCode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", sessionPresent="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->sessionPresent:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", properties="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, "]"

    .line 34
    .line 35
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
