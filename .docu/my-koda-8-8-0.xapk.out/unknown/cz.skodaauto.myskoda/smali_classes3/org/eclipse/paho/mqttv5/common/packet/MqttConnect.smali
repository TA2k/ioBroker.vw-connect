.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final KEY:Ljava/lang/String; = "Con"

.field private static final validProperties:[Ljava/lang/Byte;

.field private static final validWillProperties:[Ljava/lang/Byte;


# instance fields
.field private cleanStart:Z

.field private clientId:Ljava/lang/String;

.field private info:B

.field private keepAliveInterval:I

.field private mqttVersion:I

.field private password:[B

.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private reservedByte:Z

.field private userName:Ljava/lang/String;

.field private willDestination:Ljava/lang/String;

.field private willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

.field private willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    const/16 v0, 0x11

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/16 v0, 0x18

    .line 8
    .line 9
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const/16 v0, 0x21

    .line 14
    .line 15
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    const/16 v0, 0x27

    .line 20
    .line 21
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    const/16 v0, 0x22

    .line 26
    .line 27
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    const/16 v0, 0x19

    .line 32
    .line 33
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 34
    .line 35
    .line 36
    move-result-object v6

    .line 37
    const/16 v0, 0x17

    .line 38
    .line 39
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    const/16 v0, 0x26

    .line 44
    .line 45
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 46
    .line 47
    .line 48
    move-result-object v8

    .line 49
    const/16 v0, 0x15

    .line 50
    .line 51
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 52
    .line 53
    .line 54
    move-result-object v9

    .line 55
    const/16 v0, 0x16

    .line 56
    .line 57
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 58
    .line 59
    .line 60
    move-result-object v10

    .line 61
    filled-new-array/range {v1 .. v10}, [Ljava/lang/Byte;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    move-object v7, v8

    .line 66
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->validProperties:[Ljava/lang/Byte;

    .line 67
    .line 68
    const/4 v0, 0x1

    .line 69
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const/4 v0, 0x2

    .line 74
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    const/16 v0, 0x8

    .line 79
    .line 80
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    const/16 v0, 0x9

    .line 85
    .line 86
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    const/4 v0, 0x3

    .line 91
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    filled-new-array/range {v2 .. v8}, [Ljava/lang/Byte;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->validWillProperties:[Ljava/lang/Byte;

    .line 100
    .line 101
    return-void
.end method

.method public constructor <init>(B[B)V
    .locals 8

    const/4 v0, 0x1

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    const/4 v1, 0x5

    .line 2
    iput v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->mqttVersion:I

    .line 3
    iput-byte p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->info:B

    .line 4
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->validProperties:[Ljava/lang/Byte;

    invoke-direct {p1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 5
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->validWillProperties:[Ljava/lang/Byte;

    invoke-direct {p1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 6
    new-instance p1, Ljava/io/ByteArrayInputStream;

    invoke-direct {p1, p2}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 7
    new-instance p2, Ljava/io/DataInputStream;

    invoke-direct {p2, p1}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 8
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object p1

    .line 9
    const-string v2, "MQTT"

    invoke-virtual {p1, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_c

    .line 10
    invoke-virtual {p2}, Ljava/io/DataInputStream;->readByte()B

    move-result p1

    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->mqttVersion:I

    if-ne p1, v1, :cond_b

    .line 11
    invoke-virtual {p2}, Ljava/io/DataInputStream;->readByte()B

    move-result p1

    and-int/lit8 v1, p1, 0x1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move v1, v0

    goto :goto_0

    :cond_0
    move v1, v2

    .line 12
    :goto_0
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->reservedByte:Z

    and-int/lit8 v3, p1, 0x2

    if-eqz v3, :cond_1

    move v3, v0

    goto :goto_1

    :cond_1
    move v3, v2

    .line 13
    :goto_1
    iput-boolean v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->cleanStart:Z

    and-int/lit8 v3, p1, 0x4

    if-eqz v3, :cond_2

    move v3, v0

    goto :goto_2

    :cond_2
    move v3, v2

    :goto_2
    shr-int/lit8 v4, p1, 0x3

    const/4 v5, 0x3

    and-int/2addr v4, v5

    and-int/lit8 v6, p1, 0x20

    if-eqz v6, :cond_3

    move v6, v0

    goto :goto_3

    :cond_3
    move v6, v2

    :goto_3
    and-int/lit8 v7, p1, 0x40

    if-eqz v7, :cond_4

    move v7, v0

    goto :goto_4

    :cond_4
    move v7, v2

    :goto_4
    and-int/lit16 p1, p1, 0x80

    if-eqz p1, :cond_5

    goto :goto_5

    :cond_5
    move v0, v2

    :goto_5
    if-nez v1, :cond_a

    .line 14
    invoke-virtual {p2}, Ljava/io/DataInputStream;->readUnsignedShort()I

    move-result p1

    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->keepAliveInterval:I

    .line 15
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 16
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->clientId:Ljava/lang/String;

    if-eqz v3, :cond_7

    .line 17
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    if-eq v4, v5, :cond_6

    .line 18
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willDestination:Ljava/lang/String;

    .line 19
    invoke-virtual {p2}, Ljava/io/DataInputStream;->readShort()S

    move-result p1

    .line 20
    new-array v1, p1, [B

    .line 21
    invoke-virtual {p2, v1, v2, p1}, Ljava/io/DataInputStream;->read([BII)I

    .line 22
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    invoke-direct {p1, v1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;-><init>([B)V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 23
    invoke-virtual {p1, v4}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setQos(I)V

    .line 24
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    invoke-virtual {p1, v6}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setRetained(Z)V

    goto :goto_6

    .line 25
    :cond_6
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;

    const p1, 0xc73b

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;-><init>(I)V

    throw p0

    :cond_7
    :goto_6
    if-eqz v0, :cond_8

    .line 26
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->userName:Ljava/lang/String;

    :cond_8
    if-eqz v7, :cond_9

    .line 27
    invoke-virtual {p2}, Ljava/io/DataInputStream;->readShort()S

    move-result p1

    .line 28
    new-array v0, p1, [B

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 29
    invoke-virtual {p2, v0, v2, p1}, Ljava/io/DataInputStream;->read([BII)I

    .line 30
    :cond_9
    invoke-virtual {p2}, Ljava/io/InputStream;->close()V

    return-void

    .line 31
    :cond_a
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;

    const p1, 0xc73a

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;-><init>(I)V

    throw p0

    .line 32
    :cond_b
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;

    const p1, 0xc739

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;-><init>(I)V

    throw p0

    .line 33
    :cond_c
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;

    const p1, 0xc738

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPacketException;-><init>(I)V

    throw p0
.end method

.method public constructor <init>(Ljava/lang/String;IZILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/4 v0, 0x1

    .line 34
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    .line 35
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->clientId:Ljava/lang/String;

    .line 36
    iput p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->mqttVersion:I

    .line 37
    iput-boolean p3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->cleanStart:Z

    .line 38
    iput p4, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->keepAliveInterval:I

    if-eqz p5, :cond_0

    .line 39
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 40
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 41
    :goto_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p1, p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    .line 42
    iput-object p6, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 43
    sget-object p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->validWillProperties:[Ljava/lang/Byte;

    invoke-virtual {p6, p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
.end method


# virtual methods
.method public getClientId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->clientId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInfo()B
    .locals 0

    .line 1
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->info:B

    .line 2
    .line 3
    return p0
.end method

.method public getKeepAliveInterval()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->keepAliveInterval:I

    .line 2
    .line 3
    return p0
.end method

.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Con"

    .line 2
    .line 3
    return-object p0
.end method

.method public getMessageInfo()B
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getMqttVersion()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->mqttVersion:I

    .line 2
    .line 3
    return p0
.end method

.method public getPassword()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getPayload()[B
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
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->clientId:Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 17
    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 21
    .line 22
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    .line 27
    .line 28
    .line 29
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willDestination:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 35
    .line 36
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    array-length v2, v2

    .line 41
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 42
    .line 43
    .line 44
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 45
    .line 46
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    .line 51
    .line 52
    .line 53
    :cond_0
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->userName:Ljava/lang/String;

    .line 54
    .line 55
    if-eqz v2, :cond_1

    .line 56
    .line 57
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    :cond_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 61
    .line 62
    if-eqz v2, :cond_2

    .line 63
    .line 64
    array-length v2, v2

    .line 65
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 69
    .line 70
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 71
    .line 72
    .line 73
    :cond_2
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 77
    .line 78
    .line 79
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 80
    return-object p0

    .line 81
    :catch_0
    move-exception p0

    .line 82
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 83
    .line 84
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 85
    .line 86
    .line 87
    throw v0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUserName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->userName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVariableHeader()[B
    .locals 4

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
    const-string v2, "MQTT"

    .line 12
    .line 13
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->mqttVersion:I

    .line 17
    .line 18
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 19
    .line 20
    .line 21
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->cleanStart:Z

    .line 22
    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    int-to-byte v2, v2

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v2, 0x0

    .line 29
    :goto_0
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 30
    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    or-int/lit8 v2, v2, 0x4

    .line 34
    .line 35
    int-to-byte v2, v2

    .line 36
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    shl-int/lit8 v3, v3, 0x3

    .line 41
    .line 42
    or-int/2addr v2, v3

    .line 43
    int-to-byte v2, v2

    .line 44
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 45
    .line 46
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->isRetained()Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eqz v3, :cond_1

    .line 51
    .line 52
    or-int/lit8 v2, v2, 0x20

    .line 53
    .line 54
    int-to-byte v2, v2

    .line 55
    :cond_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->userName:Ljava/lang/String;

    .line 56
    .line 57
    if-eqz v3, :cond_2

    .line 58
    .line 59
    or-int/lit16 v2, v2, 0x80

    .line 60
    .line 61
    int-to-byte v2, v2

    .line 62
    :cond_2
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 63
    .line 64
    if-eqz v3, :cond_3

    .line 65
    .line 66
    or-int/lit8 v2, v2, 0x40

    .line 67
    .line 68
    int-to-byte v2, v2

    .line 69
    :cond_3
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 70
    .line 71
    .line 72
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->keepAliveInterval:I

    .line 73
    .line 74
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 78
    .line 79
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 90
    .line 91
    .line 92
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 93
    return-object p0

    .line 94
    :catch_0
    move-exception p0

    .line 95
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 96
    .line 97
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 98
    .line 99
    .line 100
    throw v0
.end method

.method public getWillDestination()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willDestination:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWillMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWillProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public isCleanStart()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->cleanStart:Z

    .line 2
    .line 3
    return p0
.end method

.method public isMessageIdRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public setPassword([B)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 2
    .line 3
    return-void
.end method

.method public setUserName(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->userName:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setWillDestination(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willDestination:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setWillMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

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
    const-string v1, "MqttConnect [properties="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", willProperties="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willProperties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", info="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-byte v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->info:B

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", clientId="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->clientId:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", reservedByte="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->reservedByte:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", cleanStart="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->cleanStart:Z

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", willMessage="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willMessage:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", userName="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->userName:Ljava/lang/String;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", password="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->password:[B

    .line 89
    .line 90
    invoke-static {v1}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", keepAliveInterval="

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->keepAliveInterval:I

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    const-string v1, ", willDestination="

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->willDestination:Ljava/lang/String;

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", mqttVersion="

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;->mqttVersion:I

    .line 123
    .line 124
    const-string v1, "]"

    .line 125
    .line 126
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0
.end method
