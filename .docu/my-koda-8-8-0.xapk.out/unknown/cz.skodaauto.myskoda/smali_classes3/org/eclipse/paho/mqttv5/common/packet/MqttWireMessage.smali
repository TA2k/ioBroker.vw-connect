.class public abstract Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field protected static final DEFAULT_PROTOCOL_NAME:Ljava/lang/String; = "MQTT"

.field protected static final DEFAULT_PROTOCOL_VERSION:I = 0x5

.field public static final MESSAGE_TYPE_AUTH:B = 0xft

.field public static final MESSAGE_TYPE_CONNACK:B = 0x2t

.field public static final MESSAGE_TYPE_CONNECT:B = 0x1t

.field public static final MESSAGE_TYPE_DISCONNECT:B = 0xet

.field public static final MESSAGE_TYPE_PINGREQ:B = 0xct

.field public static final MESSAGE_TYPE_PINGRESP:B = 0xdt

.field public static final MESSAGE_TYPE_PUBACK:B = 0x4t

.field public static final MESSAGE_TYPE_PUBCOMP:B = 0x7t

.field public static final MESSAGE_TYPE_PUBLISH:B = 0x3t

.field public static final MESSAGE_TYPE_PUBREC:B = 0x5t

.field public static final MESSAGE_TYPE_PUBREL:B = 0x6t

.field public static final MESSAGE_TYPE_RESERVED:B = 0x0t

.field public static final MESSAGE_TYPE_SUBACK:B = 0x9t

.field public static final MESSAGE_TYPE_SUBSCRIBE:B = 0x8t

.field public static final MESSAGE_TYPE_UNSUBACK:B = 0xbt

.field public static final MESSAGE_TYPE_UNSUBSCRIBE:B = 0xat

.field private static final PACKET_NAMES:[Ljava/lang/String;

.field private static final PACKET_RESERVED_MASKS:[B

.field protected static final STRING_ENCODING:Ljava/lang/String; = "UTF-8"


# instance fields
.field protected duplicate:Z

.field protected msgId:I

.field properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field protected reasonCode:I

.field protected reasonCodes:[I

.field private type:B


# direct methods
.method static constructor <clinit>()V
    .locals 17

    .line 1
    const-string v15, "DISCONNECT"

    .line 2
    .line 3
    const-string v16, "AUTH"

    .line 4
    .line 5
    const-string v1, "reserved"

    .line 6
    .line 7
    const-string v2, "CONNECT"

    .line 8
    .line 9
    const-string v3, "CONNACK"

    .line 10
    .line 11
    const-string v4, "PUBLISH"

    .line 12
    .line 13
    const-string v5, "PUBACK"

    .line 14
    .line 15
    const-string v6, "PUBREC"

    .line 16
    .line 17
    const-string v7, "PUBREL"

    .line 18
    .line 19
    const-string v8, "PUBCOMP"

    .line 20
    .line 21
    const-string v9, "SUBSCRIBE"

    .line 22
    .line 23
    const-string v10, "SUBACK"

    .line 24
    .line 25
    const-string v11, "UNSUBSCRIBE"

    .line 26
    .line 27
    const-string v12, "UNSUBACK"

    .line 28
    .line 29
    const-string v13, "PINGREQ"

    .line 30
    .line 31
    const-string v14, "PINGRESP"

    .line 32
    .line 33
    filled-new-array/range {v1 .. v16}, [Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->PACKET_NAMES:[Ljava/lang/String;

    .line 38
    .line 39
    const/16 v0, 0x10

    .line 40
    .line 41
    new-array v0, v0, [B

    .line 42
    .line 43
    const/4 v1, 0x6

    .line 44
    const/4 v2, 0x2

    .line 45
    aput-byte v2, v0, v1

    .line 46
    .line 47
    const/16 v1, 0x8

    .line 48
    .line 49
    aput-byte v2, v0, v1

    .line 50
    .line 51
    const/16 v1, 0xa

    .line 52
    .line 53
    aput-byte v2, v0, v1

    .line 54
    .line 55
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->PACKET_RESERVED_MASKS:[B

    .line 56
    .line 57
    return-void
.end method

.method public constructor <init>(B)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 5
    .line 6
    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    .line 13
    .line 14
    const/4 v0, -0x1

    .line 15
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->duplicate:Z

    .line 19
    .line 20
    iput-byte p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->type:B

    .line 21
    .line 22
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 23
    .line 24
    return-void
.end method

.method private static createWireMessage(Ljava/io/InputStream;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 9

    .line 9
    :try_start_0
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;

    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;-><init>(Ljava/io/InputStream;)V

    .line 10
    new-instance p0, Ljava/io/DataInputStream;

    invoke-direct {p0, v0}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 11
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result v1

    shr-int/lit8 v2, v1, 0x4

    int-to-byte v2, v2

    and-int/lit8 v1, v1, 0xf

    int-to-byte v1, v1

    .line 12
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readVariableByteInteger(Ljava/io/DataInputStream;)Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;

    move-result-object v3

    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->getValue()I

    move-result v3

    int-to-long v3, v3

    .line 13
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result v5

    int-to-long v5, v5

    add-long/2addr v5, v3

    .line 14
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result v0

    int-to-long v3, v0

    sub-long/2addr v5, v3

    const/4 v0, 0x0

    .line 15
    new-array v3, v0, [B

    const-wide/16 v7, 0x0

    cmp-long v4, v5, v7

    if-lez v4, :cond_0

    long-to-int v3, v5

    .line 16
    new-array v4, v3, [B

    .line 17
    invoke-virtual {p0, v4, v0, v3}, Ljava/io/DataInputStream;->readFully([BII)V

    move-object v3, v4

    :cond_0
    packed-switch v2, :pswitch_data_0

    const p0, 0xc352

    .line 18
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    move-result-object p0

    throw p0

    .line 19
    :pswitch_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;-><init>([B)V

    return-object p0

    .line 20
    :pswitch_1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;-><init>([B)V

    return-object p0

    .line 21
    :pswitch_2
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingResp;

    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingResp;-><init>()V

    return-object p0

    .line 22
    :pswitch_3
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingReq;

    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPingReq;-><init>()V

    return-object p0

    .line 23
    :pswitch_4
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;-><init>([B)V

    return-object p0

    .line 24
    :pswitch_5
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;-><init>([B)V

    return-object p0

    .line 25
    :pswitch_6
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubAck;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubAck;-><init>([B)V

    return-object p0

    .line 26
    :pswitch_7
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;-><init>([B)V

    return-object p0

    .line 27
    :pswitch_8
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;-><init>([B)V

    return-object p0

    .line 28
    :pswitch_9
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;-><init>([B)V

    return-object p0

    .line 29
    :pswitch_a
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;-><init>([B)V

    return-object p0

    .line 30
    :pswitch_b
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;-><init>([B)V

    return-object p0

    .line 31
    :pswitch_c
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    invoke-direct {p0, v1, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;-><init>(B[B)V

    return-object p0

    .line 32
    :pswitch_d
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;

    invoke-direct {p0, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;-><init>([B)V

    return-object p0

    .line 33
    :pswitch_e
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;

    invoke-direct {p0, v1, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnect;-><init>(B[B)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 34
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static createWireMessage(Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 8

    .line 1
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadBytes()[B

    move-result-object v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [B

    :cond_0
    move-object v5, v0

    .line 3
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/util/MultiByteArrayInputStream;

    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getHeaderBytes()[B

    move-result-object v2

    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getHeaderOffset()I

    move-result v3

    .line 4
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getHeaderLength()I

    move-result v4

    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadOffset()I

    move-result v6

    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadLength()I

    move-result v7

    .line 5
    invoke-direct/range {v1 .. v7}, Lorg/eclipse/paho/mqttv5/common/packet/util/MultiByteArrayInputStream;-><init>([BII[BII)V

    .line 6
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->createWireMessage(Ljava/io/InputStream;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    move-result-object p0

    return-object p0
.end method

.method public static createWireMessage([B)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 1

    .line 7
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, p0}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 8
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->createWireMessage(Ljava/io/InputStream;)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    move-result-object p0

    return-object p0
.end method

.method public static encodeVariableByteInteger(I)[B
    .locals 7

    .line 1
    int-to-long v0, p0

    .line 2
    new-instance p0, Ljava/io/ByteArrayOutputStream;

    .line 3
    .line 4
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 5
    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :cond_0
    const-wide/16 v3, 0x80

    .line 9
    .line 10
    rem-long v5, v0, v3

    .line 11
    .line 12
    long-to-int v5, v5

    .line 13
    int-to-byte v5, v5

    .line 14
    div-long/2addr v0, v3

    .line 15
    const-wide/16 v3, 0x0

    .line 16
    .line 17
    cmp-long v3, v0, v3

    .line 18
    .line 19
    if-lez v3, :cond_1

    .line 20
    .line 21
    or-int/lit16 v4, v5, 0x80

    .line 22
    .line 23
    int-to-byte v5, v4

    .line 24
    :cond_1
    invoke-virtual {p0, v5}, Ljava/io/ByteArrayOutputStream;->write(I)V

    .line 25
    .line 26
    .line 27
    add-int/lit8 v2, v2, 0x1

    .line 28
    .line 29
    if-lez v3, :cond_2

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    if-lt v2, v3, :cond_0

    .line 33
    .line 34
    :cond_2
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public static validateReservedBits(BB)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    .line 2
    if-ne p0, v0, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/16 v0, 0xf

    .line 6
    .line 7
    if-gt p0, v0, :cond_2

    .line 8
    .line 9
    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->PACKET_RESERVED_MASKS:[B

    .line 10
    .line 11
    aget-byte p0, v0, p0

    .line 12
    .line 13
    if-ne p1, p0, :cond_1

    .line 14
    .line 15
    :goto_0
    return-void

    .line 16
    :cond_1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 17
    .line 18
    const p1, 0xc352

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    const-string p1, "Unrecognised Message Type."

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method


# virtual methods
.method public encodeMessageId()[B
    .locals 2

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
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 12
    .line 13
    invoke-virtual {v1, p0}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 20
    .line 21
    .line 22
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    return-object p0

    .line 24
    :catch_0
    move-exception p0

    .line 25
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 26
    .line 27
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw v0
.end method

.method public getHeader()[B
    .locals 4

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getType()B

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    and-int/lit8 v0, v0, 0xf

    .line 6
    .line 7
    shl-int/lit8 v0, v0, 0x4

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageInfo()B

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    and-int/lit8 v1, v1, 0xf

    .line 14
    .line 15
    xor-int/2addr v0, v1

    .line 16
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getVariableHeader()[B

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    array-length v2, v1

    .line 21
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getPayload()[B

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    array-length p0, p0

    .line 26
    add-int/2addr v2, p0

    .line 27
    new-instance p0, Ljava/io/ByteArrayOutputStream;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 30
    .line 31
    .line 32
    new-instance v3, Ljava/io/DataOutputStream;

    .line 33
    .line 34
    invoke-direct {v3, p0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->encodeVariableByteInteger(I)[B

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v3, v0}, Ljava/io/OutputStream;->write([B)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v3, v1}, Ljava/io/OutputStream;->write([B)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/io/DataOutputStream;->flush()V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 54
    .line 55
    .line 56
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 57
    return-object p0

    .line 58
    :catch_0
    move-exception p0

    .line 59
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 60
    .line 61
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
    throw v0
.end method

.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getMessageId()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 2
    .line 3
    return p0
.end method

.method public abstract getMessageInfo()B
.end method

.method public getPayload()[B
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    new-array p0, p0, [B

    .line 3
    .line 4
    return-object p0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReasonCodes()[I
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 7
    .line 8
    const/4 v0, -0x1

    .line 9
    if-eq p0, v0, :cond_1

    .line 10
    .line 11
    filled-new-array {p0}, [I

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_1
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

.method public getType()B
    .locals 0

    .line 1
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->type:B

    .line 2
    .line 3
    return p0
.end method

.method public abstract getVariableHeader()[B
.end method

.method public isDuplicate()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->duplicate:Z

    .line 2
    .line 3
    return p0
.end method

.method public isMessageIdRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public isRetryable()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public serialize()[B
    .locals 4

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getHeader()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getPayload()[B

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    array-length v1, v0

    .line 10
    array-length v2, p0

    .line 11
    add-int/2addr v1, v2

    .line 12
    new-array v1, v1, [B

    .line 13
    .line 14
    array-length v2, v0

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-static {v0, v3, v1, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 17
    .line 18
    .line 19
    array-length v0, v0

    .line 20
    array-length v2, p0

    .line 21
    invoke-static {p0, v3, v1, v0, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 22
    .line 23
    .line 24
    return-object v1
.end method

.method public setDuplicate(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->duplicate:Z

    .line 2
    .line 3
    return-void
.end method

.method public setMessageId(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 2
    .line 3
    return-void
.end method

.method public setProperties(Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->PACKET_NAMES:[Ljava/lang/String;

    .line 2
    .line 3
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->type:B

    .line 4
    .line 5
    aget-object p0, v0, p0

    .line 6
    .line 7
    return-object p0
.end method

.method public validateReturnCode(I[I)V
    .locals 2

    .line 1
    array-length p0, p2

    .line 2
    const/4 v0, 0x0

    .line 3
    :goto_0
    if-ge v0, p0, :cond_1

    .line 4
    .line 5
    aget v1, p2, v0

    .line 6
    .line 7
    if-ne p1, v1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 14
    .line 15
    const p1, 0xc351

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method
