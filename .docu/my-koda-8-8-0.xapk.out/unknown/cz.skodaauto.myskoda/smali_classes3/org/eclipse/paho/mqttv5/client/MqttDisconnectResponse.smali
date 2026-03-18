.class public Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

.field private reasonString:Ljava/lang/String;

.field private returnCode:I

.field private serverReference:Ljava/lang/String;

.field private userProperties:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(ILjava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/lang/String;",
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->returnCode:I

    .line 5
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->reasonString:Ljava/lang/String;

    .line 6
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->userProperties:Ljava/util/ArrayList;

    .line 7
    iput-object p4, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->serverReference:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    return-void
.end method


# virtual methods
.method public getException()Lorg/eclipse/paho/mqttv5/common/MqttException;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReasonString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->reasonString:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReturnCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->returnCode:I

    .line 2
    .line 3
    return p0
.end method

.method public getServerReference()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->serverReference:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUserProperties()Ljava/util/ArrayList;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->userProperties:Ljava/util/ArrayList;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttDisconnectResponse [returnCode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->returnCode:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", reasonString="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->reasonString:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", userProperties="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->userProperties:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", serverReference="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->serverReference:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", exception="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p0, "]"

    .line 54
    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method
