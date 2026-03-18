.class public Lcom/google/android/filament/gltfio/FilamentAsset;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mEngine:Lcom/google/android/filament/Engine;

.field private mNativeObject:J

.field private mPrimaryInstance:Lcom/google/android/filament/gltfio/FilamentInstance;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/Engine;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mEngine:Lcom/google/android/filament/Engine;

    .line 5
    .line 6
    iput-wide p2, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 7
    .line 8
    return-void
.end method

.method private static native nGetBoundingBox(J[F)V
.end method

.method private static native nGetCameraEntities(J[I)V
.end method

.method private static native nGetCameraEntityCount(J)I
.end method

.method private static native nGetEntities(J[I)V
.end method

.method private static native nGetEntitiesByName(JLjava/lang/String;[I)I
.end method

.method private static native nGetEntitiesByPrefix(JLjava/lang/String;[I)I
.end method

.method private static native nGetEntityCount(J)I
.end method

.method private static native nGetExtras(JI)Ljava/lang/String;
.end method

.method private static native nGetFirstEntityByName(JLjava/lang/String;)I
.end method

.method private static native nGetInstance(J)J
.end method

.method private static native nGetLightEntities(J[I)V
.end method

.method private static native nGetLightEntityCount(J)I
.end method

.method private static native nGetMorphTargetCount(JI)I
.end method

.method private static native nGetMorphTargetNames(JI[Ljava/lang/String;)V
.end method

.method private static native nGetName(JI)Ljava/lang/String;
.end method

.method private static native nGetRenderableEntities(J[I)V
.end method

.method private static native nGetRenderableEntityCount(J)I
.end method

.method private static native nGetResourceUriCount(J)I
.end method

.method private static native nGetResourceUris(J[Ljava/lang/String;)V
.end method

.method private static native nGetRoot(J)I
.end method

.method private static native nPopRenderable(J)I
.end method

.method private static native nPopRenderables(J[I)I
.end method

.method private static native nReleaseSourceData(J)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mPrimaryInstance:Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 7
    .line 8
    return-void
.end method

.method public getBoundingBox()Lcom/google/android/filament/Box;
    .locals 10

    .line 1
    const/4 v0, 0x6

    .line 2
    new-array v0, v0, [F

    .line 3
    .line 4
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 5
    .line 6
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetBoundingBox(J[F)V

    .line 7
    .line 8
    .line 9
    new-instance v3, Lcom/google/android/filament/Box;

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    aget v4, v0, p0

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    aget v5, v0, p0

    .line 16
    .line 17
    const/4 p0, 0x2

    .line 18
    aget v6, v0, p0

    .line 19
    .line 20
    const/4 p0, 0x3

    .line 21
    aget v7, v0, p0

    .line 22
    .line 23
    const/4 p0, 0x4

    .line 24
    aget v8, v0, p0

    .line 25
    .line 26
    const/4 p0, 0x5

    .line 27
    aget v9, v0, p0

    .line 28
    .line 29
    invoke-direct/range {v3 .. v9}, Lcom/google/android/filament/Box;-><init>(FFFFFF)V

    .line 30
    .line 31
    .line 32
    return-object v3
.end method

.method public getCameraEntities()[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetCameraEntityCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [I

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetCameraEntities(J[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getEngine()Lcom/google/android/filament/Engine;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mEngine:Lcom/google/android/filament/Engine;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEntities()[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetEntityCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [I

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetEntities(J[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getEntitiesByName(Ljava/lang/String;)[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-static {v0, v1, p1, v2}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetEntitiesByName(JLjava/lang/String;[I)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    new-array v0, v0, [I

    .line 9
    .line 10
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 11
    .line 12
    invoke-static {v1, v2, p1, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetEntitiesByName(JLjava/lang/String;[I)I

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public getEntitiesByPrefix(Ljava/lang/String;)[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-static {v0, v1, p1, v2}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetEntitiesByPrefix(JLjava/lang/String;[I)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    new-array v0, v0, [I

    .line 9
    .line 10
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 11
    .line 12
    invoke-static {v1, v2, p1, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetEntitiesByPrefix(JLjava/lang/String;[I)I

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public getExtras(I)Ljava/lang/String;
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetExtras(JI)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getFirstEntityByName(Ljava/lang/String;)I
    .locals 2
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetFirstEntityByName(JLjava/lang/String;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getInstance()Lcom/google/android/filament/gltfio/FilamentInstance;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mPrimaryInstance:Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getNativeObject()J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetInstance(J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    new-instance v2, Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 15
    .line 16
    invoke-direct {v2, p0, v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;-><init>(Lcom/google/android/filament/gltfio/FilamentAsset;J)V

    .line 17
    .line 18
    .line 19
    iput-object v2, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mPrimaryInstance:Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 20
    .line 21
    return-object v2
.end method

.method public getLightEntities()[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetLightEntityCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [I

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetLightEntities(J[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getMorphTargetNames(I)[Ljava/lang/String;
    .locals 3
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetMorphTargetCount(JI)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [Ljava/lang/String;

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, p1, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetMorphTargetNames(JI[Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getName(I)Ljava/lang/String;
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetName(JI)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getNativeObject()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getRenderableEntities()[I
    .locals 3
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetRenderableEntityCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [I

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetRenderableEntities(J[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getResourceUris()[Ljava/lang/String;
    .locals 3

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetResourceUriCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v0, v0, [Ljava/lang/String;

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetResourceUris(J[Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public getRoot()I
    .locals 2
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nGetRoot(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public popRenderable()I
    .locals 2
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nPopRenderable(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public popRenderables([I)I
    .locals 2
    .param p1    # [I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nPopRenderables(J[I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public releaseSourceData()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/FilamentAsset;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;->nReleaseSourceData(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
