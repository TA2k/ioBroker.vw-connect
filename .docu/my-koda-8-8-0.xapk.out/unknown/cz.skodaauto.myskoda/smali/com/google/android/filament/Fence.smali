.class public Lcom/google/android/filament/Fence;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Fence$Mode;,
        Lcom/google/android/filament/Fence$FenceStatus;
    }
.end annotation


# static fields
.field public static final WAIT_FOR_EVER:J = -0x1L


# instance fields
.field private mNativeObject:J


# direct methods
.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/Fence;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method private static native nWait(JIJ)I
.end method

.method private static native nWaitAndDestroy(JI)I
.end method

.method public static waitAndDestroy(Lcom/google/android/filament/Fence;Lcom/google/android/filament/Fence$Mode;)Lcom/google/android/filament/Fence$FenceStatus;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Fence;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/Fence;->nWaitAndDestroy(JI)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/4 p1, -0x1

    .line 14
    if-eq p0, p1, :cond_1

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->ERROR:Lcom/google/android/filament/Fence$FenceStatus;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->CONDITION_SATISFIED:Lcom/google/android/filament/Fence$FenceStatus;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_1
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->ERROR:Lcom/google/android/filament/Fence$FenceStatus;

    .line 25
    .line 26
    return-object p0
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Fence;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Fence;->mNativeObject:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Calling method on destroyed Fence"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public wait(Lcom/google/android/filament/Fence$Mode;J)Lcom/google/android/filament/Fence$FenceStatus;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Fence;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0, p2, p3}, Lcom/google/android/filament/Fence;->nWait(JIJ)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/4 p1, -0x1

    .line 14
    if-eq p0, p1, :cond_2

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    if-eq p0, p1, :cond_0

    .line 20
    .line 21
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->ERROR:Lcom/google/android/filament/Fence$FenceStatus;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->TIMEOUT_EXPIRED:Lcom/google/android/filament/Fence$FenceStatus;

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_1
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->CONDITION_SATISFIED:Lcom/google/android/filament/Fence$FenceStatus;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    sget-object p0, Lcom/google/android/filament/Fence$FenceStatus;->ERROR:Lcom/google/android/filament/Fence$FenceStatus;

    .line 31
    .line 32
    return-object p0
.end method
