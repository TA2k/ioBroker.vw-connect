.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final validProperties:[Ljava/lang/Byte;


# instance fields
.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private topics:[Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x26

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    filled-new-array {v0}, [Ljava/lang/Byte;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->validProperties:[Ljava/lang/Byte;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>([B)V
    .locals 5

    const/16 v0, 0xa

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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

    new-array p1, p1, [Ljava/lang/String;

    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/String;

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->topics:[Ljava/lang/String;

    .line 11
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-void

    .line 12
    :cond_0
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0
.end method

.method public constructor <init>([Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/16 v0, 0xa

    .line 13
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;-><init>(B)V

    .line 14
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->topics:[Ljava/lang/String;

    if-eqz p2, :cond_0

    .line 15
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 16
    :cond_0
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 17
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    return-void
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
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->topics:[Ljava/lang/String;

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
    aget-object v4, p0, v3

    .line 26
    .line 27
    invoke-static {v1, v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V
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
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTopics()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->topics:[Ljava/lang/String;

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
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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

.method public setTopics([Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->topics:[Ljava/lang/String;

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
    const-string v1, "MqttUnsubscribe [topics="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->topics:[Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

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
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubscribe;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

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
