.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final validProperties:[Ljava/lang/Byte;


# instance fields
.field private dup:Z

.field private payload:[B

.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private qos:I

.field private retained:Z

.field private topicName:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    const/4 v0, 0x2

    .line 7
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const/16 v0, 0x23

    .line 12
    .line 13
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    const/16 v0, 0x8

    .line 18
    .line 19
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    const/16 v0, 0x9

    .line 24
    .line 25
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    const/16 v0, 0x26

    .line 30
    .line 31
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    const/4 v0, 0x3

    .line 36
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    const/16 v0, 0x7e

    .line 41
    .line 42
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 43
    .line 44
    .line 45
    move-result-object v8

    .line 46
    const/16 v0, 0xb

    .line 47
    .line 48
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 49
    .line 50
    .line 51
    move-result-object v9

    .line 52
    filled-new-array/range {v1 .. v9}, [Ljava/lang/Byte;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->validProperties:[Ljava/lang/Byte;

    .line 57
    .line 58
    return-void
.end method

.method public constructor <init>(B[B)V
    .locals 4

    const/4 v0, 0x3

    .line 13
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    const/4 v1, 0x1

    .line 14
    iput v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    const/4 v2, 0x0

    .line 15
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    .line 16
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->dup:Z

    .line 17
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v3, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v2, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    shr-int/lit8 v2, p1, 0x1

    and-int/2addr v0, v2

    .line 18
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    and-int/lit8 v0, p1, 0x1

    if-ne v0, v1, :cond_0

    .line 19
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    :cond_0
    const/16 v0, 0x8

    and-int/2addr p1, v0

    if-ne p1, v0, :cond_1

    .line 20
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->dup:Z

    .line 21
    :cond_1
    new-instance p1, Ljava/io/ByteArrayInputStream;

    invoke-direct {p1, p2}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 22
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;

    invoke-direct {v0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;-><init>(Ljava/io/InputStream;)V

    .line 23
    new-instance p1, Ljava/io/DataInputStream;

    invoke-direct {p1, v0}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 24
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->topicName:Ljava/lang/String;

    .line 25
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    if-lez v1, :cond_2

    .line 26
    invoke-virtual {p1}, Ljava/io/DataInputStream;->readUnsignedShort()I

    move-result v1

    iput v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 27
    :cond_2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {v1, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 28
    array-length p2, p2

    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result v0

    sub-int/2addr p2, v0

    new-array p2, p2, [B

    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 29
    invoke-virtual {p1, p2}, Ljava/io/DataInputStream;->readFully([B)V

    .line 30
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/4 v0, 0x3

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    const/4 v0, 0x1

    .line 2
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    const/4 v0, 0x0

    .line 3
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    .line 4
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->dup:Z

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->topicName:Ljava/lang/String;

    .line 6
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 7
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    move-result p1

    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 8
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->isDuplicate()Z

    move-result p1

    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->dup:Z

    .line 9
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->isRetained()Z

    move-result p1

    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    if-eqz p3, :cond_0

    .line 10
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 11
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 12
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
.end method


# virtual methods
.method public getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 4

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 4
    .line 5
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 6
    .line 7
    iget-boolean v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    .line 8
    .line 9
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;-><init>([BIZLorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getMessageInfo()B
    .locals 2

    .line 1
    iget v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 2
    .line 3
    shl-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    int-to-byte v0, v0

    .line 6
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x1

    .line 11
    .line 12
    int-to-byte v0, v0

    .line 13
    :cond_0
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->dup:Z

    .line 14
    .line 15
    if-nez v1, :cond_2

    .line 16
    .line 17
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->duplicate:Z

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    return v0

    .line 23
    :cond_2
    :goto_0
    or-int/lit8 p0, v0, 0x8

    .line 24
    .line 25
    int-to-byte p0, p0

    .line 26
    return p0
.end method

.method public getPayload()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getPayloadLength()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    array-length p0, p0

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getQoS()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 2
    .line 3
    return p0
.end method

.method public getTopicName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->topicName:Ljava/lang/String;

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
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->topicName:Ljava/lang/String;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const-string v2, ""

    .line 20
    .line 21
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :goto_0
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 25
    .line 26
    if-lez v2, :cond_1

    .line 27
    .line 28
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 31
    .line 32
    .line 33
    :cond_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 34
    .line 35
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 46
    .line 47
    .line 48
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 49
    return-object p0

    .line 50
    :catch_0
    move-exception p0

    .line 51
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 52
    .line 53
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 54
    .line 55
    .line 56
    throw v0
.end method

.method public isMessageIdRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getPayload()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 6
    .line 7
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 12
    .line 13
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->isDuplicate()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->dup:Z

    .line 18
    .line 19
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->isRetained()Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    .line 24
    .line 25
    return-void
.end method

.method public setTopicName(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->topicName:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 7
    .line 8
    array-length v1, v1

    .line 9
    const/16 v2, 0x14

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    move v3, v2

    .line 17
    :goto_0
    if-lt v3, v1, :cond_1

    .line 18
    .line 19
    :try_start_0
    new-instance v3, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 22
    .line 23
    const-string v5, "UTF-8"

    .line 24
    .line 25
    invoke-direct {v3, v4, v2, v1, v5}, Ljava/lang/String;-><init>([BIILjava/lang/String;)V
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :catch_0
    const-string v3, "?"

    .line 30
    .line 31
    :goto_1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v2, "MqttPublish [, qos="

    .line 34
    .line 35
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 39
    .line 40
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->qos:I

    .line 44
    .line 45
    if-lez v2, :cond_0

    .line 46
    .line 47
    const-string v2, ", messageId="

    .line 48
    .line 49
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->msgId:I

    .line 53
    .line 54
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    :cond_0
    const-string v2, ", retained="

    .line 58
    .line 59
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->retained:Z

    .line 63
    .line 64
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v2, ", duplicate="

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->duplicate:Z

    .line 73
    .line 74
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v2, ", topic="

    .line 78
    .line 79
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->topicName:Ljava/lang/String;

    .line 83
    .line 84
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v2, ", payload=[hex="

    .line 88
    .line 89
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v0, ", utf8="

    .line 96
    .line 97
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v0, ", length="

    .line 104
    .line 105
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 109
    .line 110
    array-length v0, v0

    .line 111
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string v0, "], properties="

    .line 115
    .line 116
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 120
    .line 121
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->toString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0

    .line 133
    :cond_1
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->payload:[B

    .line 134
    .line 135
    aget-byte v4, v4, v3

    .line 136
    .line 137
    invoke-static {v4}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    const/4 v6, 0x1

    .line 146
    if-ne v5, v6, :cond_2

    .line 147
    .line 148
    const-string v5, "0"

    .line 149
    .line 150
    invoke-virtual {v5, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v4

    .line 154
    :cond_2
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    add-int/lit8 v3, v3, 0x1

    .line 158
    .line 159
    goto/16 :goto_0
.end method
