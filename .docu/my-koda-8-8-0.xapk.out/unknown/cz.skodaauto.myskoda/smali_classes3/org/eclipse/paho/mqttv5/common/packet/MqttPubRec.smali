.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final validProperties:[Ljava/lang/Byte;

.field private static final validReturnCodes:[I


# instance fields
.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    const/16 v2, 0x10

    .line 7
    .line 8
    aput v2, v0, v1

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    const/16 v2, 0x80

    .line 12
    .line 13
    aput v2, v0, v1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    const/16 v2, 0x83

    .line 17
    .line 18
    aput v2, v0, v1

    .line 19
    .line 20
    const/4 v1, 0x4

    .line 21
    const/16 v2, 0x87

    .line 22
    .line 23
    aput v2, v0, v1

    .line 24
    .line 25
    const/4 v1, 0x5

    .line 26
    const/16 v2, 0x90

    .line 27
    .line 28
    aput v2, v0, v1

    .line 29
    .line 30
    const/4 v1, 0x6

    .line 31
    const/16 v2, 0x91

    .line 32
    .line 33
    aput v2, v0, v1

    .line 34
    .line 35
    const/4 v1, 0x7

    .line 36
    const/16 v2, 0x97

    .line 37
    .line 38
    aput v2, v0, v1

    .line 39
    .line 40
    const/16 v1, 0x8

    .line 41
    .line 42
    const/16 v2, 0x99

    .line 43
    .line 44
    aput v2, v0, v1

    .line 45
    .line 46
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->validReturnCodes:[I

    .line 47
    .line 48
    const/16 v0, 0x1f

    .line 49
    .line 50
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    const/16 v1, 0x26

    .line 55
    .line 56
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    filled-new-array {v0, v1}, [Ljava/lang/Byte;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->validProperties:[Ljava/lang/Byte;

    .line 65
    .line 66
    return-void
.end method

.method public constructor <init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/4 v0, 0x5

    .line 13
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    .line 14
    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->validReturnCodes:[I

    invoke-virtual {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 15
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 16
    iput p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    if-eqz p3, :cond_0

    .line 17
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 18
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 19
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
.end method

.method public constructor <init>([B)V
    .locals 6

    const/4 v0, 0x5

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 3
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 4
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;

    invoke-direct {v1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;-><init>(Ljava/io/InputStream;)V

    .line 5
    new-instance v0, Ljava/io/DataInputStream;

    invoke-direct {v0, v1}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 6
    invoke-virtual {v0}, Ljava/io/DataInputStream;->readUnsignedShort()I

    move-result v2

    iput v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 7
    array-length p1, p1

    int-to-long v2, p1

    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result p1

    int-to-long v4, p1

    sub-long/2addr v2, v4

    const-wide/16 v4, 0x1

    cmp-long p1, v2, v4

    if-ltz p1, :cond_0

    .line 8
    invoke-virtual {v0}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result p1

    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 9
    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->validReturnCodes:[I

    invoke-virtual {p0, p1, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 10
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    :goto_0
    const-wide/16 v4, 0x4

    cmp-long p1, v2, v4

    if-ltz p1, :cond_1

    .line 11
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 12
    :cond_1
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-void
.end method


# virtual methods
.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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

.method public getVariableHeader()[B
    .locals 5

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
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 12
    .line 13
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 14
    .line 15
    .line 16
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 17
    .line 18
    invoke-virtual {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    array-length v4, v2

    .line 28
    if-ne v4, v3, :cond_0

    .line 29
    .line 30
    int-to-byte p0, p0

    .line 31
    invoke-virtual {v1, p0}, Ljava/io/DataOutputStream;->write(I)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    if-nez p0, :cond_1

    .line 36
    .line 37
    array-length v4, v2

    .line 38
    if-le v4, v3, :cond_2

    .line 39
    .line 40
    :cond_1
    int-to-byte p0, p0

    .line 41
    invoke-virtual {v1, p0}, Ljava/io/DataOutputStream;->write(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    .line 45
    .line 46
    .line 47
    :cond_2
    :goto_0
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 51
    .line 52
    .line 53
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 54
    return-object p0

    .line 55
    :catch_0
    move-exception p0

    .line 56
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 57
    .line 58
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 59
    .line 60
    .line 61
    throw v0
.end method

.method public setReturnCode(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

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
    const-string v1, "MqttPubRec [returnCode="

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
    const-string v1, ", properties="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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
