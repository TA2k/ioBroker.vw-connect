.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttReceivedMessage;
.super Lorg/eclipse/paho/mqttv5/common/MqttMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getMessageId()I
    .locals 0

    .line 1
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getId()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public setDuplicate(Z)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setDuplicate(Z)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public setMessageId(I)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setId(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method
