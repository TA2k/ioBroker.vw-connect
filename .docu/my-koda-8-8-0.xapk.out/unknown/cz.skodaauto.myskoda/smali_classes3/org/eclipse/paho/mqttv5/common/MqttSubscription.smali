.class public Lorg/eclipse/paho/mqttv5/common/MqttSubscription;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private messageId:I

.field private mutable:Z

.field private noLocal:Z

.field private qos:I

.field private retainAsPublished:Z

.field private retainHandling:I

.field private topic:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->mutable:Z

    .line 3
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->qos:I

    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->noLocal:Z

    .line 5
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainAsPublished:Z

    .line 6
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainHandling:I

    .line 7
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setTopic(Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 1

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->mutable:Z

    .line 10
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->qos:I

    const/4 v0, 0x0

    .line 11
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->noLocal:Z

    .line 12
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainAsPublished:Z

    .line 13
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainHandling:I

    .line 14
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setTopic(Ljava/lang/String;)V

    .line 15
    invoke-virtual {p0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->setQos(I)V

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

.method public static validateRetainHandling(I)V
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
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->mutable:Z

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

.method public getId()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->messageId:I

    .line 2
    .line 3
    return p0
.end method

.method public getQos()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->qos:I

    .line 2
    .line 3
    return p0
.end method

.method public getRetainHandling()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainHandling:I

    .line 2
    .line 3
    return p0
.end method

.method public getTopic()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->topic:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public isNoLocal()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->noLocal:Z

    .line 2
    .line 3
    return p0
.end method

.method public isRetainAsPublished()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainAsPublished:Z

    .line 2
    .line 3
    return p0
.end method

.method public setId(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->messageId:I

    .line 2
    .line 3
    return-void
.end method

.method public setMutable(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->mutable:Z

    .line 2
    .line 3
    return-void
.end method

.method public setNoLocal(Z)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->checkMutable()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->noLocal:Z

    .line 5
    .line 6
    return-void
.end method

.method public setQos(I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->checkMutable()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->validateQos(I)V

    .line 5
    .line 6
    .line 7
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->qos:I

    .line 8
    .line 9
    return-void
.end method

.method public setRetainAsPublished(Z)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->checkMutable()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainAsPublished:Z

    .line 5
    .line 6
    return-void
.end method

.method public setRetainHandling(I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->checkMutable()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->validateRetainHandling(I)V

    .line 5
    .line 6
    .line 7
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainHandling:I

    .line 8
    .line 9
    return-void
.end method

.method public setTopic(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->checkMutable()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->topic:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttSubscription [mutable="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->mutable:Z

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", topic="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->topic:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", qos="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->qos:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", noLocal="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->noLocal:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", retainAsPublished="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainAsPublished:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", retainHandling="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;->retainHandling:I

    .line 59
    .line 60
    const-string v1, "]"

    .line 61
    .line 62
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method
