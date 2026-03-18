.class public Lcom/google/android/filament/gltfio/FilamentInstance;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mAnimator:Lcom/google/android/filament/gltfio/Animator;

.field private mAsset:Lcom/google/android/filament/gltfio/FilamentAsset;

.field private mNativeObject:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/gltfio/FilamentAsset;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mAsset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 5
    .line 6
    iput-wide p2, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mAnimator:Lcom/google/android/filament/gltfio/Animator;

    .line 10
    .line 11
    return-void
.end method

.method private static native nApplyMaterialVariant(JI)V
.end method

.method private static native nAttachSkin(JII)V
.end method

.method private static native nDetachSkin(JII)V
.end method

.method private static native nGetAnimator(J)J
.end method

.method private static native nGetEntities(J[I)V
.end method

.method private static native nGetEntityCount(J)I
.end method

.method private static native nGetJointCountAt(JI)I
.end method

.method private static native nGetJointsAt(JI[I)V
.end method

.method private static native nGetMaterialInstanceCount(J)I
.end method

.method private static native nGetMaterialInstances(J[J)V
.end method

.method private static native nGetMaterialVariantCount(J)I
.end method

.method private static native nGetMaterialVariantNames(J[Ljava/lang/String;)V
.end method

.method private static native nGetRoot(J)I
.end method

.method private static native nGetSkinCount(J)I
.end method

.method private static native nGetSkinNames(J[Ljava/lang/String;)V
.end method


# virtual methods
.method public applyMaterialVariant(I)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nApplyMaterialVariant(JI)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public attachSkin(II)V
    .locals 2
    .param p2    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/gltfio/FilamentInstance;->nAttachSkin(JII)V

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
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public detachSkin(II)V
    .locals 2
    .param p2    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/gltfio/FilamentInstance;->nDetachSkin(JII)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public getAnimator()Lcom/google/android/filament/gltfio/Animator;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mAnimator:Lcom/google/android/filament/gltfio/Animator;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    new-instance v0, Lcom/google/android/filament/gltfio/Animator;

    .line 7
    .line 8
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 9
    .line 10
    invoke-static {v1, v2}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetAnimator(J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/gltfio/Animator;-><init>(J)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mAnimator:Lcom/google/android/filament/gltfio/Animator;

    .line 18
    .line 19
    return-object v0
.end method

.method public getAsset()Lcom/google/android/filament/gltfio/FilamentAsset;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mAsset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEntities()[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetEntityCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [I

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetEntities(J[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getJointCountAt(I)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetJointCountAt(JI)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getJointsAt(I)[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/gltfio/FilamentInstance;->getJointCountAt(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [I

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getNativeObject()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v1, v2, p1, v0}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetJointsAt(JI[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getMaterialInstances()[Lcom/google/android/filament/MaterialInstance;
    .locals 7

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetMaterialInstanceCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v1, v0, [Lcom/google/android/filament/MaterialInstance;

    .line 8
    .line 9
    new-array v2, v0, [J

    .line 10
    .line 11
    iget-wide v3, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 12
    .line 13
    invoke-static {v3, v4, v2}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetMaterialInstances(J[J)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mAsset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 17
    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getEngine()Lcom/google/android/filament/Engine;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const/4 v3, 0x0

    .line 23
    :goto_0
    if-ge v3, v0, :cond_0

    .line 24
    .line 25
    new-instance v4, Lcom/google/android/filament/MaterialInstance;

    .line 26
    .line 27
    aget-wide v5, v2, v3

    .line 28
    .line 29
    invoke-direct {v4, p0, v5, v6}, Lcom/google/android/filament/MaterialInstance;-><init>(Lcom/google/android/filament/Engine;J)V

    .line 30
    .line 31
    .line 32
    aput-object v4, v1, v3

    .line 33
    .line 34
    add-int/lit8 v3, v3, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    return-object v1
.end method

.method public getMaterialVariantNames()[Ljava/lang/String;
    .locals 3

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetMaterialVariantCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [Ljava/lang/String;

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetMaterialVariantNames(J[Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getNativeObject()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getRoot()I
    .locals 2
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentInstance;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetRoot(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getSkinCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetSkinCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getSkinNames()[Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getSkinCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getNativeObject()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentInstance;->nGetSkinNames(J[Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method
