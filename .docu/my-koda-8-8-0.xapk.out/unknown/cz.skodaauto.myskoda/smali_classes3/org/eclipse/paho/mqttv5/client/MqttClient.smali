.class public Lorg/eclipse/paho/mqttv5/client/MqttClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/IMqttClient;


# instance fields
.field protected aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

.field protected timeToWait:J


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;-><init>()V

    invoke-direct {p0, p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;-><init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 3
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    const-wide/16 v0, -0x1

    .line 4
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->timeToWait:J

    .line 5
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-direct {v0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;-><init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Ljava/util/concurrent/ScheduledExecutorService;)V
    .locals 8

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 7
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    const-wide/16 v0, -0x1

    .line 8
    iput-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->timeToWait:J

    .line 9
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    const/4 v6, 0x0

    move-object v3, p1

    move-object v4, p2

    move-object v5, p3

    move-object v7, p4

    invoke-direct/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;-><init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;Lorg/eclipse/paho/mqttv5/client/MqttPingSender;Ljava/util/concurrent/ScheduledExecutorService;)V

    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    return-void
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->close(Z)V

    return-void
.end method

.method public close(Z)V
    .locals 0

    .line 2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->close(Z)V

    return-void
.end method

.method public connect()V
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;-><init>()V

    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)V

    return-void
.end method

.method public connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)V
    .locals 2

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1, v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p1

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->getTimeToWait()J

    move-result-wide v0

    invoke-interface {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion(J)V

    return-void
.end method

.method public connectWithResult(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, p1, v1, v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->getTimeToWait()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    invoke-interface {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion(J)V

    .line 13
    .line 14
    .line 15
    return-object p1
.end method

.method public disconnect()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnect()Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion()V

    return-void
.end method

.method public disconnect(J)V
    .locals 7

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    new-instance v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-wide v1, p1

    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnect(JLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    .line 3
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion()V

    return-void
.end method

.method public disconnectForcibly()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnectForcibly()V

    return-void
.end method

.method public disconnectForcibly(J)V
    .locals 0

    .line 2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnectForcibly(J)V

    return-void
.end method

.method public disconnectForcibly(JJ)V
    .locals 7

    .line 3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 4
    new-instance v6, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v6}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v5, 0x0

    move-wide v1, p1

    move-wide v3, p3

    .line 5
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    return-void
.end method

.method public disconnectForcibly(JJZ)V
    .locals 0

    .line 6
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-virtual/range {p0 .. p5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->disconnectForcibly(JJZ)V

    return-void
.end method

.method public getClientId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getClientId()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getCurrentServerURI()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getCurrentServerURI()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getDebug()Lorg/eclipse/paho/mqttv5/client/util/Debug;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getDebug()Lorg/eclipse/paho/mqttv5/client/util/Debug;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getServerURI()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getServerURI()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getTimeToWait()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->timeToWait:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getTopic(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttTopic;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->getTopic(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttTopic;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public isConnected()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->isConnected()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public messageArrivedComplete(II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->messageArrivedComplete(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 2

    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, p2, v1, v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p1

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->getTimeToWait()J

    move-result-wide v0

    invoke-interface {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion(J)V

    return-void
.end method

.method public publish(Ljava/lang/String;[BIZ)V
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    invoke-direct {v0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;-><init>([B)V

    .line 2
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setQos(I)V

    .line 3
    invoke-virtual {v0, p4}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setRetained(Z)V

    .line 4
    invoke-virtual {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    return-void
.end method

.method public reconnect()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->reconnect()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setManualAcks(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->setManualAcks(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setTimeToWait(J)V
    .locals 2

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-ltz v0, :cond_0

    .line 6
    .line 7
    iput-wide p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->timeToWait:J

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 11
    .line 12
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 13
    .line 14
    .line 15
    throw p0
.end method

.method public subscribe(Ljava/lang/String;I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 0

    .line 1
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    filled-new-array {p2}, [I

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->subscribe([Ljava/lang/String;[I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe(Ljava/lang/String;ILorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 2

    .line 9
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    filled-new-array {p2}, [I

    move-result-object p2

    const/4 v0, 0x1

    new-array v0, v0, [Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;

    const/4 v1, 0x0

    aput-object p3, v0, v1

    invoke-virtual {p0, p1, p2, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->subscribe([Ljava/lang/String;[I[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe([Ljava/lang/String;[I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 5

    .line 2
    array-length v0, p1

    array-length v1, p2

    if-ne v0, v1, :cond_1

    .line 3
    array-length v0, p1

    new-array v0, v0, [Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    const/4 v1, 0x0

    .line 4
    :goto_0
    array-length v2, p1

    if-lt v1, v2, :cond_0

    .line 5
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0

    .line 6
    :cond_0
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;

    aget-object v3, p1, v1

    aget v4, p2, v1

    invoke-direct {v2, v3, v4}, Lorg/eclipse/paho/mqttv5/common/MqttSubscription;-><init>(Ljava/lang/String;I)V

    aput-object v2, v0, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 7
    :cond_1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    const/4 p1, 0x6

    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    throw p0
.end method

.method public subscribe([Ljava/lang/String;[I[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 0

    .line 10
    invoke-virtual {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->subscribe([Ljava/lang/String;[I[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 1

    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p0

    return-object p0
.end method

.method public subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
    .locals 6

    .line 11
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    new-instance v5, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v5}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v1, p1

    move-object v4, p2

    invoke-virtual/range {v0 .. v5}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p1

    .line 12
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->getTimeToWait()J

    move-result-wide v0

    invoke-interface {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion(J)V

    return-object p1
.end method

.method public unsubscribe(Ljava/lang/String;)V
    .locals 0

    .line 1
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->unsubscribe([Ljava/lang/String;)V

    return-void
.end method

.method public unsubscribe([Ljava/lang/String;)V
    .locals 3

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttClient;->aClient:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    const/4 v2, 0x0

    invoke-virtual {v0, p1, v2, v2, v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->unsubscribe([Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    move-result-object p1

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->getTimeToWait()J

    move-result-wide v0

    invoke-interface {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->waitForCompletion(J)V

    return-void
.end method
