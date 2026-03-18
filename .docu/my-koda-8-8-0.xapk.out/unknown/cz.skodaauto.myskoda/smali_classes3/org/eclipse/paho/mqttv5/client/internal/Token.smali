.class public Lorg/eclipse/paho/mqttv5/client/internal/Token;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.Token"


# instance fields
.field private callback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

.field private client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

.field private volatile completed:Z

.field private deliveryToken:Z

.field private exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

.field private key:Ljava/lang/String;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field protected message:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

.field private messageID:I

.field private notified:Z

.field private pendingComplete:Z

.field private reasonCodes:[I

.field private request:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

.field private response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

.field private final responseLock:Ljava/lang/Object;

.field private sent:Z

.field private final sentLock:Ljava/lang/Object;

.field private topics:[Ljava/lang/String;

.field private userContext:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    .line 16
    .line 17
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->pendingComplete:Z

    .line 18
    .line 19
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sent:Z

    .line 20
    .line 21
    new-instance v1, Ljava/lang/Object;

    .line 22
    .line 23
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 27
    .line 28
    new-instance v1, Ljava/lang/Object;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->message:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 37
    .line 38
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 39
    .line 40
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->request:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 41
    .line 42
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 43
    .line 44
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->topics:[Ljava/lang/String;

    .line 45
    .line 46
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 47
    .line 48
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->callback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 49
    .line 50
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->userContext:Ljava/lang/Object;

    .line 51
    .line 52
    iput v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->messageID:I

    .line 53
    .line 54
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notified:Z

    .line 55
    .line 56
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->reasonCodes:[I

    .line 57
    .line 58
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->deliveryToken:Z

    .line 59
    .line 60
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 61
    .line 62
    invoke-interface {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public checkResult()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    throw p0
.end method

.method public getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->callback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 2
    .line 3
    return-object p0
.end method

.method public getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 2
    .line 3
    return-object p0
.end method

.method public getException()Lorg/eclipse/paho/mqttv5/common/MqttException;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGrantedQos()[I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 5
    .line 6
    instance-of v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubAck;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    check-cast p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubAck;

    .line 13
    .line 14
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubAck;->getReturnCodes()[I

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    return-object v0
.end method

.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->message:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMessageID()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->messageID:I

    .line 2
    .line 3
    return p0
.end method

.method public getReasonCodes()[I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->reasonCodes:[I

    .line 2
    .line 3
    return-object p0
.end method

.method public getRequestMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->request:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResponse()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSessionPresent()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    instance-of v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    check-cast p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;

    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttConnAck;->getSessionPresent()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public getTopics()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->topics:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUserContext()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->userContext:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWireMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public isComplete()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    .line 2
    .line 3
    return p0
.end method

.method public isCompletePending()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->pendingComplete:Z

    .line 2
    .line 3
    return p0
.end method

.method public isDeliveryToken()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->deliveryToken:Z

    .line 2
    .line 3
    return p0
.end method

.method public isInUse()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isComplete()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public isNotified()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notified:Z

    .line 2
    .line 3
    return p0
.end method

.method public markComplete(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "markComplete"

    .line 6
    .line 7
    const-string v3, "404"

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    filled-new-array {v4, p1, p2}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter v0

    .line 23
    :try_start_0
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    .line 24
    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    .line 28
    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 32
    .line 33
    if-nez v1, :cond_0

    .line 34
    .line 35
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRel;

    .line 36
    .line 37
    if-nez v1, :cond_0

    .line 38
    .line 39
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttSubAck;

    .line 40
    .line 41
    if-nez v1, :cond_0

    .line 42
    .line 43
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttUnsubAck;

    .line 44
    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :catchall_0
    move-exception p0

    .line 49
    goto :goto_1

    .line 50
    :cond_0
    :goto_0
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    if-eqz v1, :cond_1

    .line 55
    .line 56
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {p0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->updateReasonCodes([I)V

    .line 61
    .line 62
    .line 63
    :cond_1
    instance-of v1, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAck;

    .line 64
    .line 65
    if-eqz v1, :cond_2

    .line 66
    .line 67
    const/4 v1, 0x0

    .line 68
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->message:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 69
    .line 70
    :cond_2
    const/4 v1, 0x1

    .line 71
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->pendingComplete:Z

    .line 72
    .line 73
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 74
    .line 75
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 76
    .line 77
    monitor-exit v0

    .line 78
    return-void

    .line 79
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 80
    throw p0
.end method

.method public notifyComplete()V
    .locals 7

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "notifyComplete"

    .line 6
    .line 7
    const-string v3, "404"

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 14
    .line 15
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 16
    .line 17
    filled-new-array {v4, v5, v6}, [Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 25
    .line 26
    monitor-enter v0

    .line 27
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x1

    .line 31
    if-nez v1, :cond_0

    .line 32
    .line 33
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->pendingComplete:Z

    .line 34
    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    iput-boolean v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    .line 38
    .line 39
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->pendingComplete:Z

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    iput-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->pendingComplete:Z

    .line 45
    .line 46
    :goto_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/Object;->notifyAll()V

    .line 49
    .line 50
    .line 51
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 53
    .line 54
    monitor-enter v1

    .line 55
    :try_start_1
    iput-boolean v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sent:Z

    .line 56
    .line 57
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 60
    .line 61
    .line 62
    monitor-exit v1

    .line 63
    return-void

    .line 64
    :catchall_1
    move-exception p0

    .line 65
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 66
    throw p0

    .line 67
    :goto_1
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 68
    throw p0
.end method

.method public notifySent()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "notifySent"

    .line 6
    .line 7
    const-string v3, "403"

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter v0

    .line 23
    const/4 v1, 0x0

    .line 24
    :try_start_0
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    .line 28
    .line 29
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 30
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 31
    .line 32
    monitor-enter v1

    .line 33
    const/4 v0, 0x1

    .line 34
    :try_start_1
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sent:Z

    .line 35
    .line 36
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 39
    .line 40
    .line 41
    monitor-exit v1

    .line 42
    return-void

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    throw p0

    .line 46
    :catchall_1
    move-exception p0

    .line 47
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 48
    throw p0
.end method

.method public reset()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isInUse()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 8
    .line 9
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    const-string v3, "reset"

    .line 20
    .line 21
    const-string v4, "410"

    .line 22
    .line 23
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    .line 31
    .line 32
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 33
    .line 34
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sent:Z

    .line 35
    .line 36
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 37
    .line 38
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->userContext:Ljava/lang/Object;

    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 42
    .line 43
    const/16 v0, 0x7dc9

    .line 44
    .line 45
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 46
    .line 47
    .line 48
    throw p0
.end method

.method public setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->callback:Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 2
    .line 3
    return-void
.end method

.method public setClient(Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->client:Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 2
    .line 3
    return-void
.end method

.method public setDeliveryToken(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->deliveryToken:Z

    .line 2
    .line 3
    return-void
.end method

.method public setException(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public setKey(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->message:Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 2
    .line 3
    return-void
.end method

.method public setMessageID(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->messageID:I

    .line 2
    .line 3
    return-void
.end method

.method public setNotified(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notified:Z

    .line 2
    .line 3
    return-void
.end method

.method public setRequestMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->request:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    return-void
.end method

.method public setTopics([Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->topics:[Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setUserContext(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->userContext:Ljava/lang/Object;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuffer;

    .line 2
    .line 3
    const-string v1, "key="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuffer;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 13
    .line 14
    .line 15
    const-string v1, " ,topics="

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getTopics()[Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    :goto_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getTopics()[Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    array-length v2, v2

    .line 32
    if-lt v1, v2, :cond_0

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getTopics()[Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    aget-object v2, v2, v1

    .line 40
    .line 41
    invoke-virtual {v0, v2}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 42
    .line 43
    .line 44
    const-string v2, ", "

    .line 45
    .line 46
    invoke-virtual {v0, v2}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 47
    .line 48
    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    :goto_1
    const-string v1, " ,usercontext="

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getUserContext()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/Object;)Ljava/lang/StringBuffer;

    .line 62
    .line 63
    .line 64
    const-string v1, " ,isComplete="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isComplete()Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Z)Ljava/lang/StringBuffer;

    .line 74
    .line 75
    .line 76
    const-string v1, " ,isNotified="

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isNotified()Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Z)Ljava/lang/StringBuffer;

    .line 86
    .line 87
    .line 88
    const-string v1, " ,exception="

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/Object;)Ljava/lang/StringBuffer;

    .line 98
    .line 99
    .line 100
    const-string v1, " ,actioncallback="

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-virtual {v0, p0}, Ljava/lang/StringBuffer;->append(Ljava/lang/Object;)Ljava/lang/StringBuffer;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0
.end method

.method public update(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "markComplete"

    .line 6
    .line 7
    const-string v3, "411"

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    filled-new-array {v4, p1, p2}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-interface {v0, v1, v2, v3, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter p2

    .line 23
    :try_start_0
    instance-of v0, p1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubRec;

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getReasonCodes()[I

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->updateReasonCodes([I)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    :goto_0
    monitor-exit p2

    .line 44
    return-void

    .line 45
    :goto_1
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    throw p0
.end method

.method public updateReasonCodes([I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->reasonCodes:[I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->reasonCodes:[I

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    array-length v1, v0

    .line 9
    array-length v2, p1

    .line 10
    add-int/2addr v1, v2

    .line 11
    new-array v1, v1, [I

    .line 12
    .line 13
    array-length v2, v0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-static {v0, v3, v1, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->reasonCodes:[I

    .line 19
    .line 20
    array-length v0, v0

    .line 21
    array-length v2, p1

    .line 22
    invoke-static {p1, v3, v1, v0, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->reasonCodes:[I

    .line 26
    .line 27
    return-void
.end method

.method public waitForCompletion()V
    .locals 2

    const-wide/16 v0, -0x1

    .line 1
    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitForCompletion(J)V

    return-void
.end method

.method public waitForCompletion(J)V
    .locals 5

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    filled-new-array {v2, v3, p0}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "waitForCompletion"

    const-string v4, "407"

    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 3
    :try_start_0
    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitForResponse(J)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    move-result-object p1
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    .line 4
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getReasonCode()I

    move-result p2

    const/16 v0, 0x7d66

    if-ne p2, v0, :cond_2

    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_1

    .line 5
    iget-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    if-eqz p1, :cond_0

    goto :goto_1

    .line 6
    :cond_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object p2, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0, p0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "406"

    invoke-interface {p1, p2, v3, v1, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 7
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    const/16 p2, 0x7d00

    invoke-direct {p1, p2}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 8
    throw p1

    .line 9
    :cond_1
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->checkResult()Z

    return-void

    .line 10
    :cond_2
    throw p1
.end method

.method public waitForResponse()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 2

    const-wide/16 v0, -0x1

    .line 1
    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitForResponse(J)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    move-result-object p0

    return-object p0
.end method

.method public waitForResponse(J)Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 13

    .line 2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    monitor-enter v1

    .line 3
    :try_start_0
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    const-string v4, "waitForResponse"

    const-string v5, "400"

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    move-result-object v6

    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v7

    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sent:Z

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v8

    .line 5
    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v9

    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    if-nez v0, :cond_0

    const-string v10, "false"

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p0, v0

    goto/16 :goto_4

    :cond_0
    const-string v10, "true"

    :goto_0
    iget-object v11, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    move-object v12, p0

    filled-new-array/range {v6 .. v12}, [Ljava/lang/Object;

    move-result-object v6

    move-object v7, v0

    .line 6
    invoke-interface/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 7
    :cond_1
    iget-boolean p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    if-eqz p0, :cond_2

    goto :goto_3

    .line 8
    :cond_2
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const-wide/16 v2, 0x0

    if-nez p0, :cond_4

    .line 9
    :try_start_1
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    const-string v4, "waitForResponse"

    const-string v5, "408"

    invoke-virtual {v12}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    move-result-object v6

    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v7

    filled-new-array {v6, v7}, [Ljava/lang/Object;

    move-result-object v6

    invoke-interface {p0, v0, v4, v5, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    cmp-long p0, p1, v2

    if-gtz p0, :cond_3

    .line 10
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    invoke-virtual {p0}, Ljava/lang/Object;->wait()V

    goto :goto_2

    :catch_0
    move-exception v0

    move-object p0, v0

    goto :goto_1

    .line 11
    :cond_3
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    invoke-virtual {p0, p1, p2}, Ljava/lang/Object;->wait(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_2

    .line 12
    :goto_1
    :try_start_2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    iput-object v0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 13
    :cond_4
    :goto_2
    iget-boolean p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->completed:Z

    if-nez p0, :cond_1

    .line 14
    iget-object v9, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    if-nez v9, :cond_5

    cmp-long p0, p1, v2

    if-lez p0, :cond_1

    .line 15
    :goto_3
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 16
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object p1, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    const-string p2, "waitForResponse"

    const-string v0, "402"

    invoke-virtual {v12}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    move-result-object v1

    iget-object v2, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    filled-new-array {v1, v2}, [Ljava/lang/Object;

    move-result-object v1

    invoke-interface {p0, p1, p2, v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->response:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    return-object p0

    .line 18
    :cond_5
    :try_start_3
    iget-object v4, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v5, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    const-string v6, "waitForResponse"

    const-string v7, "401"

    const/4 v8, 0x0

    invoke-interface/range {v4 .. v9}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 19
    iget-object p0, v12, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    throw p0

    .line 20
    :goto_4
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p0
.end method

.method public waitUntilSent()V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->responseLock:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    :try_start_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 8
    .line 9
    if-nez v2, :cond_3

    .line 10
    .line 11
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 12
    :catch_0
    :goto_0
    :try_start_2
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sent:Z

    .line 13
    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->exception:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 19
    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x6

    .line 23
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    throw p0

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_2

    .line 30
    :cond_0
    throw p0

    .line 31
    :cond_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 32
    return-void

    .line 33
    :cond_2
    :try_start_3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 34
    .line 35
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/Token;->CLASS_NAME:Ljava/lang/String;

    .line 36
    .line 37
    const-string v3, "waitUntilSent"

    .line 38
    .line 39
    const-string v4, "409"

    .line 40
    .line 41
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    invoke-interface {v1, v2, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/Token;->sentLock:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-virtual {v1}, Ljava/lang/Object;->wait()V
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_1
    move-exception p0

    .line 59
    goto :goto_1

    .line 60
    :cond_3
    :try_start_4
    throw v2

    .line 61
    :goto_1
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 62
    :try_start_5
    throw p0

    .line 63
    :goto_2
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 64
    throw p0
.end method
