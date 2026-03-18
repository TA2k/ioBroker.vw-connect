.class Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttActionListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "MqttReconnectActionListener"
.end annotation


# instance fields
.field final methodName:Ljava/lang/String;

.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->methodName:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method

.method private rescheduleReconnectCycle(I)V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->methodName:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, ":rescheduleReconnectCycle"

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 14
    .line 15
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$0(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$1()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-string v3, "505"

    .line 24
    .line 25
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 26
    .line 27
    invoke-static {v4}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$9(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    invoke-virtual {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttSessionState;->getClientId()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$6()I

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    filled-new-array {v4, v5}, [Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-interface {v1, v2, v0, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$10()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    monitor-enter v0

    .line 55
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 56
    .line 57
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$7(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->isAutomaticReconnect()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_1

    .line 66
    .line 67
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 68
    .line 69
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$11(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Ljava/util/Timer;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    if-eqz v1, :cond_0

    .line 74
    .line 75
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 76
    .line 77
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$11(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Ljava/util/Timer;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;

    .line 82
    .line 83
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 84
    .line 85
    const/4 v3, 0x0

    .line 86
    invoke-direct {v2, p0, v3}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;)V

    .line 87
    .line 88
    .line 89
    int-to-long p0, p1

    .line 90
    invoke-virtual {v1, v2, p0, p1}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;J)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :catchall_0
    move-exception p0

    .line 95
    goto :goto_1

    .line 96
    :cond_0
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$8(I)V

    .line 97
    .line 98
    .line 99
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 100
    .line 101
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$4(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V

    .line 102
    .line 103
    .line 104
    :cond_1
    :goto_0
    monitor-exit v0

    .line 105
    return-void

    .line 106
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 107
    throw p0
.end method


# virtual methods
.method public onFailure(Lorg/eclipse/paho/mqttv5/client/IMqttToken;Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$0(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$1()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->methodName:Ljava/lang/String;

    .line 12
    .line 13
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const-string v2, "502"

    .line 26
    .line 27
    invoke-interface {p2, v0, v1, v2, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$6()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 35
    .line 36
    invoke-static {p2}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$7(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getMaxReconnectDelay()I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-ge p1, p2, :cond_0

    .line 45
    .line 46
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$6()I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    mul-int/lit8 p1, p1, 0x2

    .line 51
    .line 52
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$8(I)V

    .line 53
    .line 54
    .line 55
    :cond_0
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$6()I

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->rescheduleReconnectCycle(I)V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public onSuccess(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$0(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$1()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->methodName:Ljava/lang/String;

    .line 12
    .line 13
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/IMqttToken;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const-string v3, "501"

    .line 26
    .line 27
    invoke-interface {v0, v1, v2, v3, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 31
    .line 32
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setRestingState(Z)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectActionListener;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 39
    .line 40
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$5(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method
