.class public Lcom/google/android/filament/gltfio/Animator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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
    iput-wide p1, p0, Lcom/google/android/filament/gltfio/Animator;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method private static native nApplyAnimation(JIF)V
.end method

.method private static native nApplyCrossFade(JIFF)V
.end method

.method private static native nGetAnimationCount(J)I
.end method

.method private static native nGetAnimationDuration(JI)F
.end method

.method private static native nGetAnimationName(JI)Ljava/lang/String;
.end method

.method private static native nResetBoneMatrices(J)V
.end method

.method private static native nUpdateBoneMatrices(J)V
.end method


# virtual methods
.method public applyAnimation(IF)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/gltfio/Animator;->nApplyAnimation(JIF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public applyCrossFade(IFF)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/gltfio/Animator;->nApplyCrossFade(JIFF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/Animator;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getAnimationCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/Animator;->nGetAnimationCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getAnimationDuration(I)F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/Animator;->nGetAnimationDuration(JI)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getAnimationName(I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/Animator;->nGetAnimationName(JI)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/Animator;->mNativeObject:J

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
    const-string v0, "Using Animator on destroyed asset"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public resetBoneMatrices()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/Animator;->nResetBoneMatrices(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public updateBoneMatrices()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/Animator;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/Animator;->nUpdateBoneMatrices(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
