.class public Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.CommsTokenStore"


# instance fields
.field private closedResponse:Lorg/eclipse/paho/mqttv5/common/MqttException;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private logContext:Ljava/lang/String;

.field private final tokens:Ljava/util/Hashtable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Hashtable<",
            "Ljava/lang/String;",
            "Lorg/eclipse/paho/mqttv5/client/MqttToken;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 5
    .line 6
    const-string v1, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 7
    .line 8
    invoke-static {v1, v0}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->closedResponse:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 16
    .line 17
    invoke-interface {v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Ljava/util/Hashtable;

    .line 21
    .line 22
    invoke-direct {v1}, Ljava/util/Hashtable;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 26
    .line 27
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->logContext:Ljava/lang/String;

    .line 28
    .line 29
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 30
    .line 31
    const-string p1, "<Init>"

    .line 32
    .line 33
    const-string v1, "308"

    .line 34
    .line 35
    invoke-interface {p0, v0, p1, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public clear()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "clear"

    .line 6
    .line 7
    const-string v3, "305"

    .line 8
    .line 9
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 10
    .line 11
    invoke-virtual {v4}, Ljava/util/Hashtable;->size()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

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
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 27
    .line 28
    monitor-enter v0

    .line 29
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/util/Hashtable;->clear()V

    .line 32
    .line 33
    .line 34
    monitor-exit v0

    .line 35
    return-void

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0
.end method

.method public count()I
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/Hashtable;->size()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    monitor-exit v0

    .line 11
    return p0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    throw p0
.end method

.method public getOutstandingDelTokens()[Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    const-string v3, "getOutstandingDelTokens"

    .line 9
    .line 10
    const-string v4, "311"

    .line 11
    .line 12
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Ljava/util/Vector;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/util/Vector;-><init>()V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/util/Hashtable;->elements()Ljava/util/Enumeration;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-nez v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/util/Vector;->size()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    new-array p0, p0, [Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 37
    .line 38
    invoke-virtual {v1, p0}, Ljava/util/Vector;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, [Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 43
    .line 44
    monitor-exit v0

    .line 45
    return-object p0

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    invoke-interface {p0}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 53
    .line 54
    if-eqz v2, :cond_0

    .line 55
    .line 56
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 57
    .line 58
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isDeliveryToken()Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    if-eqz v3, :cond_0

    .line 63
    .line 64
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 65
    .line 66
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isNotified()Z

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    if-nez v3, :cond_0

    .line 71
    .line 72
    invoke-virtual {v1, v2}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    throw p0
.end method

.method public getOutstandingTokens()Ljava/util/Vector;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/client/MqttToken;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    const-string v3, "getOutstandingTokens"

    .line 9
    .line 10
    const-string v4, "312"

    .line 11
    .line 12
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Ljava/util/Vector;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/util/Vector;-><init>()V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/util/Hashtable;->elements()Ljava/util/Enumeration;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-nez v2, :cond_1

    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-object v1

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    invoke-interface {p0}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 41
    .line 42
    if-eqz v2, :cond_0

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    throw p0
.end method

.method public getToken(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 0

    .line 3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    return-object p0
.end method

.method public getToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 0

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    move-result-object p1

    .line 2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    return-object p0
.end method

.method public open()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    const-string v3, "open"

    .line 9
    .line 10
    const-string v4, "310"

    .line 11
    .line 12
    invoke-interface {v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->closedResponse:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 17
    .line 18
    monitor-exit v0

    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method

.method public quiesce(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 5
    .line 6
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    const-string v3, "quiesce"

    .line 9
    .line 10
    const-string v4, "309"

    .line 11
    .line 12
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v5

    .line 16
    invoke-interface {v1, v2, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->closedResponse:Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw p0
.end method

.method public removeToken(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 5

    .line 2
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    const-string v2, "306"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "removeToken"

    invoke-interface {v0, v1, v4, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p1, :cond_0

    .line 3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public removeToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 0

    if-eqz p1, :cond_0

    .line 1
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->removeToken(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public restoreToken(Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getMessageId()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v1}, Ljava/lang/Integer;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 17
    .line 18
    invoke-virtual {v2, v1}, Ljava/util/Hashtable;->containsKey(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 25
    .line 26
    invoke-virtual {v2, v1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 31
    .line 32
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 33
    .line 34
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 35
    .line 36
    const-string v4, "restoreToken"

    .line 37
    .line 38
    const-string v5, "302"

    .line 39
    .line 40
    filled-new-array {v1, p1, v2}, [Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-interface {p0, v3, v4, v5, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
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
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 51
    .line 52
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->logContext:Ljava/lang/String;

    .line 53
    .line 54
    invoke-direct {v2, v3}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 58
    .line 59
    const/4 v4, 0x1

    .line 60
    invoke-virtual {v3, v4}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setDeliveryToken(Z)V

    .line 61
    .line 62
    .line 63
    iget-object v3, v2, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 64
    .line 65
    invoke-virtual {v3, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setKey(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 69
    .line 70
    invoke-virtual {v3, v1, v2}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 74
    .line 75
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    .line 76
    .line 77
    const-string v4, "restoreToken"

    .line 78
    .line 79
    const-string v5, "303"

    .line 80
    .line 81
    filled-new-array {v1, p1, v2}, [Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-interface {p0, v3, v4, v5, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :goto_0
    monitor-exit v0

    .line 89
    return-object v2

    .line 90
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    throw p0
.end method

.method public saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/lang/String;)V
    .locals 6

    .line 9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    monitor-enter v0

    .line 10
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    const-string v3, "saveToken"

    const-string v4, "307"

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v5

    filled-new-array {p2, v5}, [Ljava/lang/Object;

    move-result-object v5

    invoke-interface {v1, v2, v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    iget-object v1, p1, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {v1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setKey(Ljava/lang/String;)V

    .line 12
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    invoke-virtual {p0, p2, p1}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    monitor-enter v0

    .line 2
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->closedResponse:Lorg/eclipse/paho/mqttv5/common/MqttException;

    if-nez v1, :cond_0

    .line 3
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    move-result-object v1

    .line 4
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->CLASS_NAME:Ljava/lang/String;

    const-string v4, "saveToken"

    const-string v5, "300"

    filled-new-array {v1, p2}, [Ljava/lang/Object;

    move-result-object p2

    invoke-interface {v2, v3, v4, v5, p2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 5
    invoke-virtual {p0, p1, v1}, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->saveToken(Lorg/eclipse/paho/mqttv5/client/MqttToken;Ljava/lang/String;)V

    .line 6
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 7
    :cond_0
    throw v1

    .line 8
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "line.separator"

    .line 2
    .line 3
    const-string v1, "\n"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/lang/System;->getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Ljava/lang/StringBuffer;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/lang/StringBuffer;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 15
    .line 16
    monitor-enter v2

    .line 17
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/CommsTokenStore;->tokens:Ljava/util/Hashtable;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/util/Hashtable;->elements()Ljava/util/Enumeration;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    :goto_0
    invoke-interface {p0}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-nez v3, :cond_0

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    monitor-exit v2

    .line 34
    return-object p0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    invoke-interface {p0}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 42
    .line 43
    new-instance v4, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v5, "{"

    .line 46
    .line 47
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-object v3, v3, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 51
    .line 52
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v3, "}"

    .line 56
    .line 57
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-virtual {v1, v3}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :goto_1
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 72
    throw p0
.end method
