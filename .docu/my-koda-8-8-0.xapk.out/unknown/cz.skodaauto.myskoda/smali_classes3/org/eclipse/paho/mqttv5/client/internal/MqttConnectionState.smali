.class public Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private clientId:Ljava/lang/String;

.field private incomingMaximumPacketSize:Ljava/lang/Long;

.field private incomingTopicAliasMax:Ljava/lang/Integer;

.field private keepAlive:J

.field private maximumQoS:Ljava/lang/Integer;

.field private nextOutgoingTopicAlias:Ljava/util/concurrent/atomic/AtomicInteger;

.field private outgoingMaximumPacketSize:Ljava/lang/Long;

.field private outgoingTopicAliasMaximum:Ljava/lang/Integer;

.field private receiveMaximum:Ljava/lang/Integer;

.field private retainAvailable:Ljava/lang/Boolean;

.field private sendReasonMessages:Z

.field private sharedSubscriptionsAvailable:Ljava/lang/Boolean;

.field private subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

.field private wildcardSubscriptionsAvailable:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const v0, 0xffff

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->receiveMaximum:Ljava/lang/Integer;

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->maximumQoS:Ljava/lang/Integer;

    .line 19
    .line 20
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 21
    .line 22
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->retainAvailable:Ljava/lang/Boolean;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->outgoingMaximumPacketSize:Ljava/lang/Long;

    .line 26
    .line 27
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->incomingMaximumPacketSize:Ljava/lang/Long;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->outgoingTopicAliasMaximum:Ljava/lang/Integer;

    .line 35
    .line 36
    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->incomingTopicAliasMax:Ljava/lang/Integer;

    .line 37
    .line 38
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 39
    .line 40
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 41
    .line 42
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->sharedSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 43
    .line 44
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->sendReasonMessages:Z

    .line 45
    .line 46
    const-wide/16 v0, 0x3c

    .line 47
    .line 48
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->keepAlive:J

    .line 49
    .line 50
    const-string v0, ""

    .line 51
    .line 52
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->clientId:Ljava/lang/String;

    .line 53
    .line 54
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 58
    .line 59
    .line 60
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->nextOutgoingTopicAlias:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 61
    .line 62
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->clientId:Ljava/lang/String;

    .line 63
    .line 64
    return-void
.end method


# virtual methods
.method public clearConnectionState()V
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->nextOutgoingTopicAlias:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public getClientId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->clientId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIncomingMaximumPacketSize()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->incomingMaximumPacketSize:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIncomingTopicAliasMax()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->incomingTopicAliasMax:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getKeepAlive()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->keepAlive:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getMaximumQoS()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->maximumQoS:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getNextOutgoingTopicAlias()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->nextOutgoingTopicAlias:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public getOutgoingMaximumPacketSize()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->outgoingMaximumPacketSize:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getOutgoingTopicAliasMaximum()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->outgoingTopicAliasMaximum:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReceiveMaximum()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->receiveMaximum:Ljava/lang/Integer;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const p0, 0xffff

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :cond_0
    return-object p0
.end method

.method public isRetainAvailable()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->retainAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSendReasonMessages()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->sendReasonMessages:Z

    .line 2
    .line 3
    return p0
.end method

.method public isSharedSubscriptionsAvailable()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->sharedSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSubscriptionIdentifiersAvailable()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public isWildcardSubscriptionsAvailable()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public setIncomingMaximumPacketSize(Ljava/lang/Long;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->incomingMaximumPacketSize:Ljava/lang/Long;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setIncomingTopicAliasMax(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->incomingTopicAliasMax:Ljava/lang/Integer;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setKeepAliveSeconds(J)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x3e8

    .line 2
    .line 3
    mul-long/2addr p1, v0

    .line 4
    iput-wide p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->keepAlive:J

    .line 5
    .line 6
    return-void
.end method

.method public setMaximumQoS(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->maximumQoS:Ljava/lang/Integer;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setOutgoingMaximumPacketSize(Ljava/lang/Long;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->outgoingMaximumPacketSize:Ljava/lang/Long;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setOutgoingTopicAliasMaximum(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->outgoingTopicAliasMaximum:Ljava/lang/Integer;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setReceiveMaximum(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->receiveMaximum:Ljava/lang/Integer;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setRetainAvailable(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->retainAvailable:Ljava/lang/Boolean;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setSendReasonMessages(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->sendReasonMessages:Z

    .line 2
    .line 3
    return-void
.end method

.method public setSharedSubscriptionsAvailable(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->sharedSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setSubscriptionIdentifiersAvailable(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 4
    .line 5
    :cond_0
    return-void
.end method

.method public setWildcardSubscriptionsAvailable(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttConnectionState;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 4
    .line 5
    :cond_0
    return-void
.end method
