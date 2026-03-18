.class public Lorg/eclipse/paho/mqttv5/common/MqttMessage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private dup:Z

.field private messageId:I

.field private mutable:Z

.field private payload:[B

.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

.field private qos:I

.field private retained:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->mutable:Z

    .line 3
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->qos:I

    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->retained:Z

    .line 5
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->dup:Z

    .line 6
    new-array v0, v0, [B

    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setPayload([B)V

    return-void
.end method

.method public constructor <init>([B)V
    .locals 1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->mutable:Z

    .line 9
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->qos:I

    const/4 v0, 0x0

    .line 10
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->retained:Z

    .line 11
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->dup:Z

    .line 12
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setPayload([B)V

    return-void
.end method

.method public constructor <init>([BIZLorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 14
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->mutable:Z

    .line 15
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->qos:I

    const/4 v0, 0x0

    .line 16
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->retained:Z

    .line 17
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->dup:Z

    .line 18
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setPayload([B)V

    .line 19
    invoke-virtual {p0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setQos(I)V

    .line 20
    invoke-virtual {p0, p3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setRetained(Z)V

    .line 21
    invoke-virtual {p0, p4}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setProperties(Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    return-void
.end method

.method public static validateQos(I)V
    .locals 1

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    if-gt p0, v0, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 10
    .line 11
    .line 12
    throw p0
.end method


# virtual methods
.method public checkMutable()V
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->mutable:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public clearPayload()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->checkMutable()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    new-array v0, v0, [B

    .line 6
    .line 7
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->payload:[B

    .line 8
    .line 9
    return-void
.end method

.method public getId()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->messageId:I

    .line 2
    .line 3
    return p0
.end method

.method public getPayload()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->payload:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getQos()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->qos:I

    .line 2
    .line 3
    return p0
.end method

.method public isDuplicate()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->dup:Z

    .line 2
    .line 3
    return p0
.end method

.method public isRetained()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->retained:Z

    .line 2
    .line 3
    return p0
.end method

.method public setDuplicate(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->dup:Z

    .line 2
    .line 3
    return-void
.end method

.method public setId(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->messageId:I

    .line 2
    .line 3
    return-void
.end method

.method public setMutable(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->mutable:Z

    .line 2
    .line 3
    return-void
.end method

.method public setPayload([B)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->checkMutable()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->payload:[B

    .line 8
    .line 9
    return-void
.end method

.method public setProperties(Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-void
.end method

.method public setQos(I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->checkMutable()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->validateQos(I)V

    .line 5
    .line 6
    .line 7
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->qos:I

    .line 8
    .line 9
    return-void
.end method

.method public setRetained(Z)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->checkMutable()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->retained:Z

    .line 5
    .line 6
    return-void
.end method

.method public toDebugString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttMessage [mutable="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->mutable:Z

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", payload="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    new-instance v1, Ljava/lang/String;

    .line 19
    .line 20
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->payload:[B

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/String;-><init>([B)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", qos="

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->qos:I

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string v1, ", retained="

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->retained:Z

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", dup="

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->dup:Z

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string v1, ", messageId="

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->messageId:I

    .line 64
    .line 65
    const-string v1, "]"

    .line 66
    .line 67
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->payload:[B

    .line 4
    .line 5
    invoke-direct {v0, p0}, Ljava/lang/String;-><init>([B)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method
