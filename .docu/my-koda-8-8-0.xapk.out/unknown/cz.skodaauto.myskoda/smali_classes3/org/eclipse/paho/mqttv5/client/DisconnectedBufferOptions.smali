.class public Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final DELETE_OLDEST_MESSAGES_DEFAULT:Z = false

.field public static final DISCONNECTED_BUFFER_ENABLED_DEFAULT:Z = false

.field public static final DISCONNECTED_BUFFER_SIZE_DEFAULT:I = 0x1388

.field public static final PERSIST_DISCONNECTED_BUFFER_DEFAULT:Z = false


# instance fields
.field private bufferEnabled:Z

.field private bufferSize:I

.field private deleteOldestMessages:Z

.field private persistBuffer:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x1388

    .line 5
    .line 6
    iput v0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->bufferSize:I

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->bufferEnabled:Z

    .line 10
    .line 11
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->persistBuffer:Z

    .line 12
    .line 13
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->deleteOldestMessages:Z

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public getBufferSize()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->bufferSize:I

    .line 2
    .line 3
    return p0
.end method

.method public isBufferEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->bufferEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isDeleteOldestMessages()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->deleteOldestMessages:Z

    .line 2
    .line 3
    return p0
.end method

.method public isPersistBuffer()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->persistBuffer:Z

    .line 2
    .line 3
    return p0
.end method

.method public setBufferEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->bufferEnabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public setBufferSize(I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-lt p1, v0, :cond_0

    .line 3
    .line 4
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->bufferSize:I

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 10
    .line 11
    .line 12
    throw p0
.end method

.method public setDeleteOldestMessages(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->deleteOldestMessages:Z

    .line 2
    .line 3
    return-void
.end method

.method public setPersistBuffer(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;->persistBuffer:Z

    .line 2
    .line 3
    return-void
.end method
