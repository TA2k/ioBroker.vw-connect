.class public Lcom/google/android/filament/utils/RemoteServer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;
    }
.end annotation


# instance fields
.field private mNativeObject:J


# direct methods
.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lcom/google/android/filament/utils/RemoteServer;->nCreate(I)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 9
    .line 10
    const-wide/16 p0, 0x0

    .line 11
    .line 12
    cmp-long p0, v0, p0

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string p1, "Couldn\'t create RemoteServer"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0
.end method

.method public static isBinary(Ljava/lang/String;)Z
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    const-string v0, ".json"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public static isJson(Ljava/lang/String;)Z
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    const-string v0, ".json"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method private static native nAcquireReceivedMessage(JLjava/nio/ByteBuffer;I)V
.end method

.method private static native nCreate(I)J
.end method

.method private static native nDestroy(J)V
.end method

.method private static native nPeekIncomingLabel(J)Ljava/lang/String;
.end method

.method private static native nPeekReceivedBufferLength(J)I
.end method

.method private static native nPeekReceivedLabel(J)Ljava/lang/String;
.end method


# virtual methods
.method public acquireReceivedMessage()Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/RemoteServer;->nPeekReceivedBufferLength(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    new-instance v1, Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;

    .line 12
    .line 13
    invoke-direct {v1}, Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;-><init>()V

    .line 14
    .line 15
    .line 16
    iget-wide v2, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 17
    .line 18
    invoke-static {v2, v3}, Lcom/google/android/filament/utils/RemoteServer;->nPeekReceivedLabel(J)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    iput-object v2, v1, Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;->label:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    iput-object v2, v1, Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;->buffer:Ljava/nio/ByteBuffer;

    .line 29
    .line 30
    sget-object v3, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 31
    .line 32
    invoke-virtual {v2, v3}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 33
    .line 34
    .line 35
    iget-wide v2, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 36
    .line 37
    iget-object p0, v1, Lcom/google/android/filament/utils/RemoteServer$ReceivedMessage;->buffer:Ljava/nio/ByteBuffer;

    .line 38
    .line 39
    invoke-static {v2, v3, p0, v0}, Lcom/google/android/filament/utils/RemoteServer;->nAcquireReceivedMessage(JLjava/nio/ByteBuffer;I)V

    .line 40
    .line 41
    .line 42
    return-object v1
.end method

.method public close()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/RemoteServer;->nDestroy(J)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 9
    .line 10
    return-void
.end method

.method public finalize()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/RemoteServer;->nDestroy(J)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public peekIncomingLabel()Ljava/lang/String;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/RemoteServer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/RemoteServer;->nPeekIncomingLabel(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
