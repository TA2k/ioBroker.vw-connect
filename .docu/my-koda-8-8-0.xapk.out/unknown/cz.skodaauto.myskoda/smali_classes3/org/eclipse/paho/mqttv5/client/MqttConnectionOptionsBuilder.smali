.class public Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 5
    .line 6
    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public authData([B)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setAuthData([B)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public authMethod(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setAuthMethod(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public automaticReconnect(Z)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setAutomaticReconnect(Z)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public automaticReconnectDelay(II)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setAutomaticReconnectDelay(II)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public cleanStart(Z)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setCleanStart(Z)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public connectionTimeout(I)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setConnectionTimeout(I)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public keepAliveInterval(I)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setKeepAliveInterval(I)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public maximumPacketSize(Ljava/lang/Long;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setMaximumPacketSize(Ljava/lang/Long;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public password([B)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setPassword([B)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public requestProblemInfo(Ljava/lang/Boolean;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setRequestProblemInfo(Z)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public requestReponseInfo(Ljava/lang/Boolean;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setRequestResponseInfo(Z)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public serverURI(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setServerURIs([Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public serverURIs([Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setServerURIs([Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public sessionExpiryInterval(Ljava/lang/Long;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setSessionExpiryInterval(Ljava/lang/Long;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public topicAliasMaximum(Ljava/lang/Integer;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setTopicAliasMaximum(Ljava/lang/Integer;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public userProperties(Ljava/util/ArrayList;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;)",
            "Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setUserProperties(Ljava/util/List;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public username(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setUserName(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public will(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptionsBuilder;->mqttConnectionOptions:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setWill(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
