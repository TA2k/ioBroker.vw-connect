.class public Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;
    }
.end annotation


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.CommsCallback"

.field private static final INBOUND_QUEUE_SIZE:I = 0xa


# instance fields
.field private callbackFuture:Ljava/util/concurrent/Future;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/Future<",
            "*>;"
        }
    .end annotation
.end field

.field private callbackMap:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/Integer;",
            "Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;",
            ">;"
        }
    .end annotation
.end field

.field private callbackThread:Ljava/lang/Thread;

.field private callbackTopicMap:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

.field private completeQueue:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/client/MqttToken;",
            ">;"
        }
    .end annotation
.end field

.field private current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

.field private final lifecycle:Ljava/lang/Object;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private manualAcks:Z

.field private messageHandlerId:Ljava/util/concurrent/atomic/AtomicInteger;

.field private messageQueue:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;",
            ">;"
        }
    .end annotation
.end field

.field private mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

.field private reconnectInternalCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

.field private final spaceAvailable:Ljava/lang/Object;

.field private subscriptionIdMap:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/Integer;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

.field private threadName:Ljava/lang/String;

.field private final workAvailable:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageHandlerId:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 21
    .line 22
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 23
    .line 24
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 25
    .line 26
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 27
    .line 28
    new-instance v0, Ljava/lang/Object;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 34
    .line 35
    new-instance v0, Ljava/lang/Object;

    .line 36
    .line 37
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 41
    .line 42
    new-instance v0, Ljava/lang/Object;

    .line 43
    .line 44
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 48
    .line 49
    iput-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->manualAcks:Z

    .line 50
    .line 51
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 52
    .line 53
    new-instance v0, Ljava/util/ArrayList;

    .line 54
    .line 55
    const/16 v1, 0xa

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 58
    .line 59
    .line 60
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 61
    .line 62
    new-instance v0, Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 65
    .line 66
    .line 67
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 68
    .line 69
    new-instance v0, Ljava/util/HashMap;

    .line 70
    .line 71
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 72
    .line 73
    .line 74
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    .line 75
    .line 76
    new-instance v0, Ljava/util/HashMap;

    .line 77
    .line 78
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 79
    .line 80
    .line 81
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    .line 82
    .line 83
    new-instance v0, Ljava/util/HashMap;

    .line 84
    .line 85
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    .line 89
    .line 90
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 91
    .line 92
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-interface {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    return-void
.end method

.method private handleActionComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 5

    .line 1
    monitor-enter p1

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 3
    .line 4
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 5
    .line 6
    const-string v2, "handleActionComplete"

    .line 7
    .line 8
    const-string v3, "705"

    .line 9
    .line 10
    iget-object v4, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 11
    .line 12
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->isComplete()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_2

    .line 37
    :cond_0
    :goto_0
    iget-object v0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 38
    .line 39
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->notifyComplete()V

    .line 40
    .line 41
    .line 42
    iget-object v0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 43
    .line 44
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isNotified()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_2

    .line 49
    .line 50
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 51
    .line 52
    if-eqz v0, :cond_1

    .line 53
    .line 54
    iget-object v0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 55
    .line 56
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isDeliveryToken()Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->isComplete()Z

    .line 63
    .line 64
    .line 65
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 66
    if-eqz v0, :cond_1

    .line 67
    .line 68
    :try_start_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 69
    .line 70
    invoke-interface {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->deliveryComplete(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :catchall_1
    move-exception v0

    .line 75
    :try_start_2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 76
    .line 77
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 78
    .line 79
    const-string v3, "handleActionComplete"

    .line 80
    .line 81
    const-string v4, "726"

    .line 82
    .line 83
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-interface {v1, v2, v3, v4, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_1
    :goto_1
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->fireActionEvent(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 91
    .line 92
    .line 93
    :cond_2
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->isComplete()Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    if-eqz p0, :cond_4

    .line 98
    .line 99
    iget-object p0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 100
    .line 101
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isDeliveryToken()Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-nez p0, :cond_3

    .line 106
    .line 107
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    if-eqz p0, :cond_4

    .line 112
    .line 113
    :cond_3
    iget-object p0, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 114
    .line 115
    const/4 v0, 0x1

    .line 116
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setNotified(Z)V

    .line 117
    .line 118
    .line 119
    :cond_4
    monitor-exit p1

    .line 120
    return-void

    .line 121
    :goto_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 122
    throw p0
.end method

.method private handleMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getTopicName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 6
    .line 7
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    filled-new-array {v3, v0}, [Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    const-string v4, "handleMessage"

    .line 22
    .line 23
    const-string v5, "713"

    .line 24
    .line 25
    invoke-interface {v1, v2, v4, v5, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-virtual {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->deliverMessage(Ljava/lang/String;ILorg/eclipse/paho/mqttv5/common/MqttMessage;)Z

    .line 37
    .line 38
    .line 39
    iget-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->manualAcks:Z

    .line 40
    .line 41
    if-nez v0, :cond_0

    .line 42
    .line 43
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getQos()I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    const/4 v1, 0x1

    .line 52
    if-ne v0, v1, :cond_0

    .line 53
    .line 54
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 55
    .line 56
    new-instance v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    .line 57
    .line 58
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 63
    .line 64
    invoke-direct {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 65
    .line 66
    .line 67
    const/4 v3, 0x0

    .line 68
    invoke-direct {v1, v3, p1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 69
    .line 70
    .line 71
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 72
    .line 73
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 74
    .line 75
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0, v1, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 87
    .line 88
    .line 89
    :cond_0
    return-void
.end method


# virtual methods
.method public areQueuesEmpty()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    :goto_0
    monitor-exit v0

    .line 26
    return p0

    .line 27
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    throw p0
.end method

.method public asyncOperationComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v1

    .line 10
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 16
    .line 17
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 18
    .line 19
    const-string v3, "asyncOperationComplete"

    .line 20
    .line 21
    const-string v4, "715"

    .line 22
    .line 23
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 24
    .line 25
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-interface {v0, v2, v3, v4, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

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
    move-exception v0

    .line 44
    move-object p0, v0

    .line 45
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    throw p0

    .line 47
    :cond_0
    :try_start_1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->handleActionComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    :try_end_1
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_1 .. :try_end_1} :catch_0

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :catch_0
    move-exception v0

    .line 52
    move-object v7, v0

    .line 53
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 54
    .line 55
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 56
    .line 57
    const-string v4, "asyncOperationComplete"

    .line 58
    .line 59
    const-string v5, "719"

    .line 60
    .line 61
    const/4 v6, 0x0

    .line 62
    invoke-interface/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 66
    .line 67
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 68
    .line 69
    invoke-direct {p1, v7}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 70
    .line 71
    .line 72
    const/4 v0, 0x0

    .line 73
    invoke-virtual {p0, v0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public authMessageReceived(Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->getReturnCode()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, v1, p1}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->authPacketArrived(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception p1

    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 19
    .line 20
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 21
    .line 22
    const-string v1, "727"

    .line 23
    .line 24
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string v2, "authMessageReceived"

    .line 29
    .line 30
    invoke-interface {p0, v0, v2, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void
.end method

.method public connectionLost(Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V
    .locals 5

    .line 1
    const-string v0, "connectionLost"

    .line 2
    .line 3
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    if-eqz p2, :cond_0

    .line 8
    .line 9
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 10
    .line 11
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 12
    .line 13
    const-string v3, "722"

    .line 14
    .line 15
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-interface {v1, v2, v0, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;

    .line 27
    .line 28
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getReturnCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getReasonString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getUserProperties()Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    check-cast v4, Ljava/util/ArrayList;

    .line 49
    .line 50
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getServerReference()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    invoke-direct {v1, v2, v3, v4, p2}, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;-><init>(ILjava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 62
    .line 63
    invoke-interface {p2, v1}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->disconnected(Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :catchall_0
    move-exception p1

    .line 68
    goto :goto_1

    .line 69
    :cond_0
    if-eqz v1, :cond_1

    .line 70
    .line 71
    if-eqz p1, :cond_1

    .line 72
    .line 73
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 74
    .line 75
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 76
    .line 77
    const-string v2, "708"

    .line 78
    .line 79
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    invoke-interface {p2, v1, v0, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    new-instance p2, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;

    .line 87
    .line 88
    invoke-direct {p2, p1}, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;-><init>(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 89
    .line 90
    .line 91
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 92
    .line 93
    invoke-interface {v1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->disconnected(Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;)V

    .line 94
    .line 95
    .line 96
    :cond_1
    :goto_0
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->reconnectInternalCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 97
    .line 98
    if-eqz p2, :cond_2

    .line 99
    .line 100
    if-eqz p1, :cond_2

    .line 101
    .line 102
    new-instance p2, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;

    .line 103
    .line 104
    invoke-direct {p2, p1}, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;-><init>(Lorg/eclipse/paho/mqttv5/common/MqttException;)V

    .line 105
    .line 106
    .line 107
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->reconnectInternalCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 108
    .line 109
    invoke-interface {p1, p2}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->disconnected(Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 110
    .line 111
    .line 112
    :cond_2
    return-void

    .line 113
    :goto_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 114
    .line 115
    sget-object p2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 116
    .line 117
    const-string v1, "720"

    .line 118
    .line 119
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-interface {p0, p2, v0, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    return-void
.end method

.method public deliverMessage(Ljava/lang/String;ILorg/eclipse/paho/mqttv5/common/MqttMessage;)Z
    .locals 5

    .line 1
    invoke-virtual {p3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getSubscriptionIdentifiers()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Ljava/util/Map$Entry;

    .line 39
    .line 40
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    check-cast v4, Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v4, p1}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->isMatched(Ljava/lang/String;Ljava/lang/String;)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-eqz v4, :cond_0

    .line 51
    .line 52
    invoke-virtual {p3, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setId(I)V

    .line 53
    .line 54
    .line 55
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    .line 56
    .line 57
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;

    .line 66
    .line 67
    invoke-interface {v2, p1, p3}, Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;->messageArrived(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 68
    .line 69
    .line 70
    move v2, v1

    .line 71
    goto :goto_0

    .line 72
    :cond_2
    invoke-virtual {p3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getSubscriptionIdentifiers()Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-nez v3, :cond_5

    .line 89
    .line 90
    :goto_2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 91
    .line 92
    if-eqz v0, :cond_4

    .line 93
    .line 94
    if-nez v2, :cond_4

    .line 95
    .line 96
    invoke-virtual {p3, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setId(I)V

    .line 97
    .line 98
    .line 99
    :try_start_0
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 100
    .line 101
    invoke-interface {p2, p1, p3}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->messageArrived(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 102
    .line 103
    .line 104
    goto :goto_3

    .line 105
    :catch_0
    move-exception p1

    .line 106
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 107
    .line 108
    sget-object p2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 109
    .line 110
    const-string p3, "725"

    .line 111
    .line 112
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    const-string v0, "deliverMessage"

    .line 117
    .line 118
    invoke-interface {p0, p2, v0, p3, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :goto_3
    return v1

    .line 122
    :cond_4
    return v2

    .line 123
    :cond_5
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    check-cast v3, Ljava/lang/Integer;

    .line 128
    .line 129
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    .line 130
    .line 131
    invoke-virtual {v4, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v4

    .line 135
    if-eqz v4, :cond_3

    .line 136
    .line 137
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    .line 138
    .line 139
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    check-cast v2, Ljava/lang/Integer;

    .line 144
    .line 145
    invoke-virtual {p3, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setId(I)V

    .line 146
    .line 147
    .line 148
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    .line 149
    .line 150
    invoke-virtual {v3, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;

    .line 155
    .line 156
    invoke-interface {v2, p1, p3}, Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;->messageArrived(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 157
    .line 158
    .line 159
    move v2, v1

    .line 160
    goto :goto_1
.end method

.method public doesSubscriptionIdentifierExist(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public fireActionEvent(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 5

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "716"

    .line 14
    .line 15
    const-string v3, "fireActionEvent"

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 20
    .line 21
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v4, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 24
    .line 25
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    invoke-interface {p0, v1, v3, v2, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttActionListener;->onSuccess(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 41
    .line 42
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v4, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 45
    .line 46
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getKey()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    invoke-interface {p0, v1, v3, v2, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-interface {v0, p1, p0}, Lorg/eclipse/paho/mqttv5/client/MqttActionListener;->onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
    :cond_1
    return-void
.end method

.method public getThread()Ljava/lang/Thread;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackThread:Ljava/lang/Thread;

    .line 2
    .line 3
    return-object p0
.end method

.method public isQuiesced()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiescing()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->areQueuesEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

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

.method public isQuiescing()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->QUIESCING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 7
    .line 8
    if-ne p0, v1, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    monitor-exit v0

    .line 14
    return p0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method

.method public isRunning()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->QUIESCING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 11
    .line 12
    if-ne v1, v3, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    goto :goto_2

    .line 17
    :cond_0
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 18
    .line 19
    if-ne p0, v2, :cond_1

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    :goto_1
    monitor-exit v0

    .line 25
    return p0

    .line 26
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method

.method public messageArrived(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/HashMap;->size()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-lez v0, :cond_3

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 14
    .line 15
    monitor-enter v0

    .line 16
    :catch_0
    :goto_0
    :try_start_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_2

    .line 21
    .line 22
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiescing()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_2

    .line 27
    .line 28
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 31
    .line 32
    .line 33
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    const/16 v2, 0xa

    .line 35
    .line 36
    if-ge v1, v2, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    :try_start_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 40
    .line 41
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 42
    .line 43
    const-string v3, "messageArrived"

    .line 44
    .line 45
    const-string v4, "709"

    .line 46
    .line 47
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 51
    .line 52
    const-wide/16 v2, 0xc8

    .line 53
    .line 54
    invoke-virtual {v1, v2, v3}, Ljava/lang/Object;->wait(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_0
    move-exception p0

    .line 59
    goto :goto_3

    .line 60
    :cond_2
    :goto_1
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 61
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiescing()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_3

    .line 66
    .line 67
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 68
    .line 69
    monitor-enter v0

    .line 70
    :try_start_3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 76
    .line 77
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 78
    .line 79
    const-string v2, "messageArrived"

    .line 80
    .line 81
    const-string v3, "710"

    .line 82
    .line 83
    invoke-interface {p1, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 89
    .line 90
    .line 91
    monitor-exit v0

    .line 92
    goto :goto_2

    .line 93
    :catchall_1
    move-exception p0

    .line 94
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 95
    throw p0

    .line 96
    :cond_3
    :goto_2
    return-void

    .line 97
    :goto_3
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 98
    throw p0
.end method

.method public messageArrivedComplete(II)V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 6
    .line 7
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;

    .line 8
    .line 9
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 10
    .line 11
    invoke-direct {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-direct {v0, v1, p1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubAck;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 18
    .line 19
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 20
    .line 21
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p2, v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    if-ne p2, v0, :cond_1

    .line 38
    .line 39
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 40
    .line 41
    invoke-virtual {p2, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->deliveryComplete(I)V

    .line 42
    .line 43
    .line 44
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;

    .line 45
    .line 46
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 47
    .line 48
    invoke-direct {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-direct {p2, v1, p1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;-><init>(IILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 55
    .line 56
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPubComp;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    const-string v2, "messageArrivedComplete"

    .line 67
    .line 68
    const-string v3, "723"

    .line 69
    .line 70
    invoke-interface {p1, v0, v2, v3, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->info(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 74
    .line 75
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 76
    .line 77
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-direct {p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p0, p2, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 89
    .line 90
    .line 91
    :cond_1
    return-void
.end method

.method public mqttErrorOccurred(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getMessage()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const-string v3, "mqttErrorOccurred"

    .line 14
    .line 15
    const-string v4, "721"

    .line 16
    .line 17
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->warning(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    :try_start_0
    invoke-interface {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttCallback;->mqttErrorOccurred(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catch_0
    move-exception p1

    .line 29
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 30
    .line 31
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 32
    .line 33
    const-string v1, "724"

    .line 34
    .line 35
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-interface {p0, v0, v3, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    return-void
.end method

.method public quiesce()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->QUIESCING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 11
    .line 12
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 19
    .line 20
    monitor-enter v1

    .line 21
    :try_start_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 22
    .line 23
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 24
    .line 25
    const-string v3, "quiesce"

    .line 26
    .line 27
    const-string v4, "711"

    .line 28
    .line 29
    invoke-interface {v0, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 35
    .line 36
    .line 37
    monitor-exit v1

    .line 38
    return-void

    .line 39
    :catchall_1
    move-exception p0

    .line 40
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 41
    throw p0

    .line 42
    :goto_1
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 43
    throw p0
.end method

.method public removeMessageListener(Ljava/lang/Integer;)V
    .locals 3

    .line 7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    .line 8
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_1

    return-void

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    .line 11
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2, p1}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    .line 12
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0
.end method

.method public removeMessageListener(Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    .line 2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    invoke-virtual {v1, v0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    invoke-virtual {p1}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_1

    return-void

    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    .line 5
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2, v0}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    .line 6
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0
.end method

.method public removeMessageListeners()V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/util/HashMap;->clear()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public run()V
    .locals 8

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackThread:Ljava/lang/Thread;

    .line 6
    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->threadName:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v1

    .line 15
    :try_start_0
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 16
    .line 17
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 18
    .line 19
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_9

    .line 20
    :goto_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x0

    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 28
    .line 29
    monitor-enter v2

    .line 30
    :try_start_1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 31
    .line 32
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 33
    .line 34
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackThread:Ljava/lang/Thread;

    .line 36
    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception v0

    .line 39
    move-object p0, v0

    .line 40
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 41
    throw p0

    .line 42
    :cond_0
    :try_start_3
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 43
    .line 44
    monitor-enter v2
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 45
    :try_start_4
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-eqz v0, :cond_1

    .line 66
    .line 67
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 68
    .line 69
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 70
    .line 71
    const-string v4, "run"

    .line 72
    .line 73
    const-string v5, "704"

    .line 74
    .line 75
    invoke-interface {v0, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/Object;->wait()V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :catchall_1
    move-exception v0

    .line 85
    goto :goto_2

    .line 86
    :cond_1
    :goto_1
    monitor-exit v2

    .line 87
    goto :goto_3

    .line 88
    :goto_2
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 89
    :try_start_5
    throw v0
    :try_end_5
    .catch Ljava/lang/InterruptedException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 90
    :catchall_2
    move-exception v0

    .line 91
    move-object v7, v0

    .line 92
    goto/16 :goto_9

    .line 93
    .line 94
    :catch_0
    :goto_3
    :try_start_6
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    if-eqz v0, :cond_5

    .line 99
    .line 100
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 101
    .line 102
    monitor-enter v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 103
    :try_start_7
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    const/4 v3, 0x0

    .line 110
    if-nez v0, :cond_2

    .line 111
    .line 112
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 113
    .line 114
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    check-cast v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 119
    .line 120
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 121
    .line 122
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    goto :goto_4

    .line 126
    :catchall_3
    move-exception v0

    .line 127
    goto :goto_7

    .line 128
    :cond_2
    move-object v0, v1

    .line 129
    :goto_4
    monitor-exit v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 130
    if-eqz v0, :cond_3

    .line 131
    .line 132
    :try_start_8
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->handleActionComplete(Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 133
    .line 134
    .line 135
    :cond_3
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 136
    .line 137
    monitor-enter v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 138
    :try_start_9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 139
    .line 140
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    if-nez v0, :cond_4

    .line 145
    .line 146
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 147
    .line 148
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 153
    .line 154
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 155
    .line 156
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    goto :goto_5

    .line 160
    :catchall_4
    move-exception v0

    .line 161
    goto :goto_6

    .line 162
    :cond_4
    move-object v0, v1

    .line 163
    :goto_5
    monitor-exit v2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 164
    if-eqz v0, :cond_5

    .line 165
    .line 166
    :try_start_a
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->handleMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 167
    .line 168
    .line 169
    goto :goto_8

    .line 170
    :goto_6
    :try_start_b
    monitor-exit v2
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 171
    :try_start_c
    throw v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_2

    .line 172
    :goto_7
    :try_start_d
    monitor-exit v2
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_3

    .line 173
    :try_start_e
    throw v0

    .line 174
    :cond_5
    :goto_8
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isQuiescing()Z

    .line 175
    .line 176
    .line 177
    move-result v0

    .line 178
    if-eqz v0, :cond_6

    .line 179
    .line 180
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 181
    .line 182
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->checkQuiesceLock()Z
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_2

    .line 183
    .line 184
    .line 185
    :cond_6
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 186
    .line 187
    monitor-enter v2

    .line 188
    :try_start_f
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 189
    .line 190
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 191
    .line 192
    const-string v3, "run"

    .line 193
    .line 194
    const-string v4, "706"

    .line 195
    .line 196
    invoke-interface {v0, v1, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 200
    .line 201
    invoke-virtual {v0}, Ljava/lang/Object;->notifyAll()V

    .line 202
    .line 203
    .line 204
    monitor-exit v2

    .line 205
    goto/16 :goto_0

    .line 206
    .line 207
    :catchall_5
    move-exception v0

    .line 208
    move-object p0, v0

    .line 209
    monitor-exit v2
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_5

    .line 210
    throw p0

    .line 211
    :goto_9
    :try_start_10
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 212
    .line 213
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 214
    .line 215
    const-string v4, "run"

    .line 216
    .line 217
    const-string v5, "714"

    .line 218
    .line 219
    const/4 v6, 0x0

    .line 220
    invoke-interface/range {v2 .. v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 221
    .line 222
    .line 223
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientComms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 224
    .line 225
    new-instance v2, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 226
    .line 227
    invoke-direct {v2, v7}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v0, v1, v2, v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->shutdownConnection(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/MqttException;Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_7

    .line 231
    .line 232
    .line 233
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 234
    .line 235
    monitor-enter v1

    .line 236
    :try_start_11
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 237
    .line 238
    const-string v2, "run"

    .line 239
    .line 240
    const-string v4, "706"

    .line 241
    .line 242
    invoke-interface {v0, v3, v2, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 246
    .line 247
    invoke-virtual {v0}, Ljava/lang/Object;->notifyAll()V

    .line 248
    .line 249
    .line 250
    monitor-exit v1

    .line 251
    goto/16 :goto_0

    .line 252
    .line 253
    :catchall_6
    move-exception v0

    .line 254
    move-object p0, v0

    .line 255
    monitor-exit v1
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_6

    .line 256
    throw p0

    .line 257
    :catchall_7
    move-exception v0

    .line 258
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 259
    .line 260
    monitor-enter v2

    .line 261
    :try_start_12
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 262
    .line 263
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 264
    .line 265
    const-string v4, "run"

    .line 266
    .line 267
    const-string v5, "706"

    .line 268
    .line 269
    invoke-interface {v1, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->spaceAvailable:Ljava/lang/Object;

    .line 273
    .line 274
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 275
    .line 276
    .line 277
    monitor-exit v2
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_8

    .line 278
    throw v0

    .line 279
    :catchall_8
    move-exception v0

    .line 280
    move-object p0, v0

    .line 281
    :try_start_13
    monitor-exit v2
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_8

    .line 282
    throw p0

    .line 283
    :catchall_9
    move-exception v0

    .line 284
    move-object p0, v0

    .line 285
    :try_start_14
    monitor-exit v1
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_9

    .line 286
    throw p0
.end method

.method public setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->mqttCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 2
    .line 3
    return-void
.end method

.method public setClientState(Lorg/eclipse/paho/mqttv5/client/internal/ClientState;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 2
    .line 3
    return-void
.end method

.method public setManualAcks(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->manualAcks:Z

    .line 2
    .line 3
    return-void
.end method

.method public setMessageListener(Ljava/lang/Integer;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageHandlerId:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackMap:Ljava/util/HashMap;

    .line 8
    .line 9
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {v1, v2, p3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    iget-object p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackTopicMap:Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p3, p2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->subscriptionIdMap:Ljava/util/HashMap;

    .line 28
    .line 29
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    :cond_0
    return-void
.end method

.method public setReconnectCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->reconnectInternalCallback:Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 2
    .line 3
    return-void
.end method

.method public start(Ljava/lang/String;Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->threadName:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter p1

    .line 6
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->current_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 7
    .line 8
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 9
    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    :try_start_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->messageQueue:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->completeQueue:Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 23
    .line 24
    .line 25
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 26
    :try_start_2
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->RUNNING:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 27
    .line 28
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 29
    .line 30
    if-nez p2, :cond_0

    .line 31
    .line 32
    new-instance p2, Ljava/lang/Thread;

    .line 33
    .line 34
    invoke-direct {p2, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/Thread;->start()V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    goto :goto_2

    .line 43
    :cond_0
    invoke-interface {p2, p0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackFuture:Ljava/util/concurrent/Future;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_1
    move-exception p0

    .line 51
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 52
    :try_start_4
    throw p0

    .line 53
    :cond_1
    :goto_0
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 54
    :catch_0
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    if-eqz p1, :cond_2

    .line 59
    .line 60
    return-void

    .line 61
    :cond_2
    const-wide/16 p1, 0x64

    .line 62
    .line 63
    :try_start_5
    invoke-static {p1, p2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :goto_2
    :try_start_6
    monitor-exit p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 68
    throw p0
.end method

.method public stop()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackFuture:Ljava/util/concurrent/Future;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-interface {v1, v2}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_3

    .line 15
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_3

    .line 21
    .line 22
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 23
    .line 24
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 25
    .line 26
    const-string v2, "stop"

    .line 27
    .line 28
    const-string v3, "700"

    .line 29
    .line 30
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->lifecycle:Ljava/lang/Object;

    .line 34
    .line 35
    monitor-enter v0

    .line 36
    :try_start_1
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;->STOPPED:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 37
    .line 38
    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->target_state:Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback$State;

    .line 39
    .line 40
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 41
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackThread:Ljava/lang/Thread;

    .line 46
    .line 47
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_2

    .line 52
    .line 53
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 54
    .line 55
    monitor-enter v0

    .line 56
    :try_start_2
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 57
    .line 58
    const-string v3, "stop"

    .line 59
    .line 60
    const-string v4, "701"

    .line 61
    .line 62
    invoke-interface {v2, v1, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->workAvailable:Ljava/lang/Object;

    .line 66
    .line 67
    invoke-virtual {v1}, Ljava/lang/Object;->notifyAll()V

    .line 68
    .line 69
    .line 70
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 71
    :goto_1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->isRunning()Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-nez v0, :cond_1

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_1
    const-wide/16 v0, 0x64

    .line 79
    .line 80
    :try_start_3
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 81
    .line 82
    .line 83
    :catch_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 84
    .line 85
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->notifyQueueLock()V

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :catchall_1
    move-exception p0

    .line 90
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 91
    throw p0

    .line 92
    :cond_2
    :goto_2
    const/4 v0, 0x0

    .line 93
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->callbackThread:Ljava/lang/Thread;

    .line 94
    .line 95
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 96
    .line 97
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsCallback;->CLASS_NAME:Ljava/lang/String;

    .line 98
    .line 99
    const-string v1, "stop"

    .line 100
    .line 101
    const-string v2, "703"

    .line 102
    .line 103
    invoke-interface {p0, v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    return-void

    .line 107
    :catchall_2
    move-exception p0

    .line 108
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 109
    throw p0

    .line 110
    :cond_3
    return-void

    .line 111
    :goto_3
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 112
    throw p0
.end method
