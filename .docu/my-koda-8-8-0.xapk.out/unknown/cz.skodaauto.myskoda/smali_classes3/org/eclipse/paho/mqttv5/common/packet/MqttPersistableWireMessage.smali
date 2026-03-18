.class public abstract Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/common/MqttPersistable;


# direct methods
.method public constructor <init>(B)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getHeaderBytes()[B
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-class v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getTopicAlias()Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-virtual {v0, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setTopicAlias(Ljava/lang/Integer;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getHeader()[B

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-virtual {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setTopicAlias(Ljava/lang/Integer;)V

    .line 36
    .line 37
    .line 38
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 39
    .line 40
    return-object v2

    .line 41
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getHeader()[B

    .line 42
    .line 43
    .line 44
    move-result-object p0
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    return-object p0

    .line 46
    :catch_0
    move-exception p0

    .line 47
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 48
    .line 49
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getCause()Ljava/lang/Throwable;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>(Ljava/lang/Throwable;)V

    .line 54
    .line 55
    .line 56
    throw v0
.end method

.method public getHeaderLength()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPersistableWireMessage;->getHeaderBytes()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    array-length p0, p0

    .line 6
    return p0
.end method

.method public getHeaderOffset()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getPayloadBytes()[B
    .locals 1

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getPayload()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    move-exception p0

    .line 7
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getCause()Ljava/lang/Throwable;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>(Ljava/lang/Throwable;)V

    .line 14
    .line 15
    .line 16
    throw v0
.end method

.method public getPayloadLength()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getPayloadOffset()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
