.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;
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
    const/4 v0, 0x7

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    const/16 v2, 0x11

    .line 6
    .line 7
    aput v2, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x2

    .line 10
    const/16 v2, 0x80

    .line 11
    .line 12
    aput v2, v0, v1

    .line 13
    .line 14
    const/4 v1, 0x3

    .line 15
    const/16 v2, 0x83

    .line 16
    .line 17
    aput v2, v0, v1

    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    const/16 v2, 0x87

    .line 21
    .line 22
    aput v2, v0, v1

    .line 23
    .line 24
    const/4 v1, 0x5

    .line 25
    const/16 v2, 0x8f

    .line 26
    .line 27
    aput v2, v0, v1

    .line 28
    .line 29
    const/4 v1, 0x6

    .line 30
    const/16 v2, 0x91

    .line 31
    .line 32
    aput v2, v0, v1

    .line 33
    .line 34
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->validReturnCodes:[I

    .line 35
    .line 36
    const/16 v0, 0x1f

    .line 37
    .line 38
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    const/16 v1, 0x26

    .line 43
    .line 44
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    filled-new-array {v0, v1}, [Ljava/lang/Byte;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->validProperties:[Ljava/lang/Byte;

    .line 53
    .line 54
    return-void
.end method

.method public constructor <init>([B)V
    .locals 4

    const/16 v0, 0xb

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {v2, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 8
    array-length p1, p1

    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result v1

    sub-int/2addr p1, v1

    .line 9
    new-array v1, p1, [I

    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    const/4 v1, 0x0

    :goto_0
    if-lt v1, p1, :cond_0

    .line 10
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-void

    .line 11
    :cond_0
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    invoke-virtual {v0}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result v3

    aput v3, v2, v1

    .line 12
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    aget v2, v2, v1

    sget-object v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->validReturnCodes:[I

    invoke-virtual {p0, v2, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0
.end method

.method public constructor <init>([ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 4

    const/16 v0, 0xb

    .line 13
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    .line 14
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-lt v1, v0, :cond_1

    .line 15
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    if-eqz p2, :cond_0

    .line 16
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_1

    .line 17
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 18
    :goto_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void

    .line 19
    :cond_1
    aget v2, p1, v1

    .line 20
    sget-object v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->validReturnCodes:[I

    invoke-virtual {p0, v2, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0
.end method


# virtual methods
.method public getPayload()[B
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
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    .line 12
    .line 13
    array-length v2, p0

    .line 14
    const/4 v3, 0x0

    .line 15
    :goto_0
    if-lt v3, v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    aget v4, p0, v3

    .line 26
    .line 27
    invoke-virtual {v1, v4}, Ljava/io/DataOutputStream;->writeByte(I)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    .line 29
    .line 30
    add-int/lit8 v3, v3, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catch_0
    move-exception p0

    .line 34
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReturnCodes()[I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    .line 2
    .line 3
    return-object p0
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
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 12
    .line 13
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 17
    .line 18
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 29
    .line 30
    .line 31
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    return-object p0

    .line 33
    :catch_0
    move-exception p0

    .line 34
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttUnsubAck [returnCodes="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCodes:[I

    .line 9
    .line 10
    invoke-static {v1}, Ljava/util/Arrays;->toString([I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", properties="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string p0, "]"

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
