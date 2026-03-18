.class public Lcom/google/android/filament/android/FilamentHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synchronizePendingFrames(Lcom/google/android/filament/Engine;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->createFence()Lcom/google/android/filament/Fence;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lcom/google/android/filament/Fence$Mode;->FLUSH:Lcom/google/android/filament/Fence$Mode;

    .line 6
    .line 7
    const-wide/16 v2, -0x1

    .line 8
    .line 9
    invoke-virtual {v0, v1, v2, v3}, Lcom/google/android/filament/Fence;->wait(Lcom/google/android/filament/Fence$Mode;J)Lcom/google/android/filament/Fence$FenceStatus;

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lcom/google/android/filament/Engine;->destroyFence(Lcom/google/android/filament/Fence;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
