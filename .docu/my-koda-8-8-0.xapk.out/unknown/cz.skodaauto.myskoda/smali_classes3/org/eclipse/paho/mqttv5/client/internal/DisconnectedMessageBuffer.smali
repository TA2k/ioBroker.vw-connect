.class public Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.DisconnectedMessageBuffer"


# instance fields
.field private final bufLock:Ljava/lang/Object;

.field private buffer:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/eclipse/paho/mqttv5/client/BufferedMessage;",
            ">;"
        }
    .end annotation
.end field

.field private bufferOpts:Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;

.field private callback:Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    new-instance v0, Ljava/lang/Object;

    .line 15
    .line 16
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufLock:Ljava/lang/Object;

    .line 20
    .line 21
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufferOpts:Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;

    .line 22
    .line 23
    new-instance p1, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public deleteMessage(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public getMessage(I)Lorg/eclipse/paho/mqttv5/client/BufferedMessage;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public getMessageCount()I
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

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

.method public isPersistBuffer()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufferOpts:Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->isPersistBuffer()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public putMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 2

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;-><init>(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufLock:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter p1

    .line 9
    :try_start_0
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufferOpts:Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;

    .line 16
    .line 17
    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->getBufferSize()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-ge p2, v1, :cond_0

    .line 22
    .line 23
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->bufferOpts:Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;

    .line 32
    .line 33
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->isDeleteOldestMessages()Z

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    if-eqz p2, :cond_1

    .line 38
    .line 39
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    invoke-virtual {p2, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->buffer:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    :goto_0
    monitor-exit p1

    .line 51
    return-void

    .line 52
    :cond_1
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 53
    .line 54
    const/16 p2, 0x7dcb

    .line 55
    .line 56
    invoke-direct {p0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 61
    throw p0
.end method

.method public run()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "516"

    .line 6
    .line 7
    const-string v3, "run"

    .line 8
    .line 9
    invoke-interface {v0, v1, v3, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :catch_0
    :goto_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->getMessageCount()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-gtz v0, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    const/4 v0, 0x0

    .line 20
    :try_start_0
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->getMessage(I)Lorg/eclipse/paho/mqttv5/client/BufferedMessage;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->callback:Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;

    .line 25
    .line 26
    invoke-interface {v2, v1}, Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;->publishBufferedMessage(Lorg/eclipse/paho/mqttv5/client/BufferedMessage;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->deleteMessage(I)V
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_1

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catch_1
    move-exception v0

    .line 34
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getReasonCode()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/16 v2, 0x7dca

    .line 39
    .line 40
    if-ne v1, v2, :cond_1

    .line 41
    .line 42
    const-wide/16 v0, 0x64

    .line 43
    .line 44
    :try_start_1
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 49
    .line 50
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->CLASS_NAME:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getMessage()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    const-string v2, "519"

    .line 61
    .line 62
    invoke-interface {p0, v1, v3, v2, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->warning(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :goto_1
    return-void
.end method

.method public setPublishCallback(Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/DisconnectedMessageBuffer;->callback:Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;

    .line 2
    .line 3
    return-void
.end method
