.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttPingResp;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final KEY:Ljava/lang/String; = "Ping"


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    const/16 v0, 0xd

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;-><init>(B)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Ping"

    .line 2
    .line 3
    return-object p0
.end method

.method public getMessageInfo()B
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getVariableHeader()[B
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    new-array p0, p0, [B

    .line 3
    .line 4
    return-object p0
.end method

.method public isMessageIdRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
