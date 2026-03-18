.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final validProperties:[Ljava/lang/Byte;


# instance fields
.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0xb

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/16 v1, 0x7f

    .line 8
    .line 9
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const/16 v2, 0x26

    .line 14
    .line 15
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    filled-new-array {v0, v1, v2}, [Ljava/lang/Byte;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->validProperties:[Ljava/lang/Byte;

    .line 24
    .line 25
    return-void
.end method

.method public constructor <init>(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/16 v0, 0x8

    .line 20
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    .line 21
    filled-new-array {p1}, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    .line 22
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 23
    sget-object p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p2, p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
.end method

.method public constructor <init>([B)V
    .locals 5

    const/16 v0, 0x8

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {v2, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 8
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 9
    :goto_0
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->getCounter()I

    move-result v3

    array-length v4, p1

    if-lt v3, v4, :cond_0

    .line 10
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result p1

    new-array p1, p1, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    .line 11
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-void

    .line 12
    :cond_0
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object v3

    .line 13
    invoke-virtual {v0}, Ljava/io/DataInputStream;->readByte()B

    move-result v4

    .line 14
    invoke-direct {p0, v3, v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->decodeSubscription(Ljava/lang/String;B)Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0
.end method

.method public constructor <init>([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/16 v0, 0x8

    .line 15
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    .line 16
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    if-eqz p2, :cond_0

    .line 17
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 18
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 19
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
.end method

.method private decodeSubscription(Ljava/lang/String;B)Lorg/eclipse/paho/mqttv5/common/MqttSubscription;
    .locals 2

    .line 1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    and-int/lit8 p1, p2, 0x3

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setQos(I)V

    .line 9
    .line 10
    .line 11
    and-int/lit8 p1, p2, 0x4

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/4 v1, 0x1

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    move p1, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move p1, v0

    .line 20
    :goto_0
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setNoLocal(Z)V

    .line 21
    .line 22
    .line 23
    and-int/lit8 p1, p2, 0x8

    .line 24
    .line 25
    if-eqz p1, :cond_1

    .line 26
    .line 27
    move v0, v1

    .line 28
    :cond_1
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setRetainAsPublished(Z)V

    .line 29
    .line 30
    .line 31
    shr-int/lit8 p1, p2, 0x4

    .line 32
    .line 33
    and-int/lit8 p1, p1, 0x3

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setRetainHandling(I)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method

.method private encodeSubscription(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)[B
    .locals 3

    .line 1
    :try_start_0
    new-instance p0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/io/DataOutputStream;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getTopic()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getQos()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    int-to-byte v1, v1

    .line 23
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->isNoLocal()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    or-int/lit8 v1, v1, 0x4

    .line 30
    .line 31
    int-to-byte v1, v1

    .line 32
    :cond_0
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->isRetainAsPublished()Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    or-int/lit8 v1, v1, 0x8

    .line 39
    .line 40
    int-to-byte v1, v1

    .line 41
    :cond_1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->getRetainHandling()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    shl-int/lit8 p1, p1, 0x4

    .line 46
    .line 47
    or-int/2addr p1, v1

    .line 48
    int-to-byte p1, p1

    .line 49
    invoke-virtual {v0, p1}, Ljava/io/DataOutputStream;->write(I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/io/DataOutputStream;->flush()V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 56
    .line 57
    .line 58
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 59
    return-object p0

    .line 60
    :catch_0
    move-exception p0

    .line 61
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 62
    .line 63
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    throw p1
.end method


# virtual methods
.method public getMessageInfo()B
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->duplicate:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/16 p0, 0x8

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    :goto_0
    or-int/lit8 p0, p0, 0x2

    .line 10
    .line 11
    int-to-byte p0, p0

    .line 12
    return p0
.end method

.method public getPayload()[B
    .locals 6

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
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    .line 12
    .line 13
    array-length v3, v2

    .line 14
    const/4 v4, 0x0

    .line 15
    :goto_0
    if-lt v4, v3, :cond_0

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
    aget-object v5, v2, v4

    .line 26
    .line 27
    invoke-direct {p0, v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->encodeSubscription(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)[B

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-virtual {v1, v5}, Ljava/io/OutputStream;->write([B)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    .line 33
    .line 34
    add-int/lit8 v4, v4, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :catch_0
    move-exception p0

    .line 38
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 39
    .line 40
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 41
    .line 42
    .line 43
    throw v0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSubscriptions()[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

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
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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

.method public isRetryable()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttSubscribe [properties="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", subscriptions="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubscribe;->subscriptions:[Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    .line 19
    .line 20
    invoke-static {p0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
