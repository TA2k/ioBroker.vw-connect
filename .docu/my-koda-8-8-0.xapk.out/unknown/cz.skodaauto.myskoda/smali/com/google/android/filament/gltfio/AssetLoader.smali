.class public Lcom/google/android/filament/gltfio/AssetLoader;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mEngine:Lcom/google/android/filament/Engine;

.field private mMaterialCache:Lcom/google/android/filament/gltfio/MaterialProvider;

.field private mNativeObject:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/Engine;Lcom/google/android/filament/gltfio/MaterialProvider;Lcom/google/android/filament/EntityManager;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    invoke-virtual {p3}, Lcom/google/android/filament/EntityManager;->getNativeObject()J

    .line 9
    .line 10
    .line 11
    move-result-wide v2

    .line 12
    invoke-static {v0, v1, p2, v2, v3}, Lcom/google/android/filament/gltfio/AssetLoader;->nCreateAssetLoader(JLjava/lang/Object;J)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 17
    .line 18
    const-wide/16 v2, 0x0

    .line 19
    .line 20
    cmp-long p3, v0, v2

    .line 21
    .line 22
    if-eqz p3, :cond_0

    .line 23
    .line 24
    iput-object p1, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mEngine:Lcom/google/android/filament/Engine;

    .line 25
    .line 26
    iput-object p2, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mMaterialCache:Lcom/google/android/filament/gltfio/MaterialProvider;

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "Unable to parse glTF asset."

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method private static native nCreateAsset(JLjava/nio/Buffer;I)J
.end method

.method private static native nCreateAssetLoader(JLjava/lang/Object;J)J
.end method

.method private static native nCreateInstance(JJ)J
.end method

.method private static native nCreateInstancedAsset(JLjava/nio/Buffer;I[J)J
.end method

.method private static native nDestroyAsset(JJ)V
.end method

.method private static native nDestroyAssetLoader(J)V
.end method

.method private static native nEnableDiagnostics(JZ)V
.end method


# virtual methods
.method public createAsset(Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/FilamentAsset;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    invoke-static {v0, v1, p1, v2}, Lcom/google/android/filament/gltfio/AssetLoader;->nCreateAsset(JLjava/nio/Buffer;I)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    const-wide/16 v2, 0x0

    .line 12
    .line 13
    cmp-long p1, v0, v2

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    new-instance p1, Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 18
    .line 19
    iget-object p0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mEngine:Lcom/google/android/filament/Engine;

    .line 20
    .line 21
    invoke-direct {p1, p0, v0, v1}, Lcom/google/android/filament/gltfio/FilamentAsset;-><init>(Lcom/google/android/filament/Engine;J)V

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public createInstance(Lcom/google/android/filament/gltfio/FilamentAsset;)Lcom/google/android/filament/gltfio/FilamentInstance;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/gltfio/AssetLoader;->nCreateInstance(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    const-wide/16 v2, 0x0

    .line 12
    .line 13
    cmp-long p0, v0, v2

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return-object p0

    .line 19
    :cond_0
    new-instance p0, Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 20
    .line 21
    invoke-direct {p0, p1, v0, v1}, Lcom/google/android/filament/gltfio/FilamentInstance;-><init>(Lcom/google/android/filament/gltfio/FilamentAsset;J)V

    .line 22
    .line 23
    .line 24
    return-object p0
.end method

.method public createInstancedAsset(Ljava/nio/Buffer;[Lcom/google/android/filament/gltfio/FilamentInstance;)Lcom/google/android/filament/gltfio/FilamentAsset;
    .locals 6

    .line 1
    array-length v0, p2

    .line 2
    new-array v1, v0, [J

    .line 3
    .line 4
    iget-wide v2, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 7
    .line 8
    .line 9
    move-result v4

    .line 10
    invoke-static {v2, v3, p1, v4, v1}, Lcom/google/android/filament/gltfio/AssetLoader;->nCreateInstancedAsset(JLjava/nio/Buffer;I[J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    const-wide/16 v4, 0x0

    .line 15
    .line 16
    cmp-long p1, v2, v4

    .line 17
    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return-object p0

    .line 22
    :cond_0
    new-instance p1, Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 23
    .line 24
    iget-object p0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mEngine:Lcom/google/android/filament/Engine;

    .line 25
    .line 26
    invoke-direct {p1, p0, v2, v3}, Lcom/google/android/filament/gltfio/FilamentAsset;-><init>(Lcom/google/android/filament/Engine;J)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x0

    .line 30
    :goto_0
    if-ge p0, v0, :cond_1

    .line 31
    .line 32
    new-instance v2, Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 33
    .line 34
    aget-wide v3, v1, p0

    .line 35
    .line 36
    invoke-direct {v2, p1, v3, v4}, Lcom/google/android/filament/gltfio/FilamentInstance;-><init>(Lcom/google/android/filament/gltfio/FilamentAsset;J)V

    .line 37
    .line 38
    .line 39
    aput-object v2, p2, p0

    .line 40
    .line 41
    add-int/lit8 p0, p0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    return-object p1
.end method

.method public destroy()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/AssetLoader;->nDestroyAssetLoader(J)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 9
    .line 10
    return-void
.end method

.method public destroyAsset(Lcom/google/android/filament/gltfio/FilamentAsset;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/gltfio/AssetLoader;->nDestroyAsset(JJ)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->clearNativeObject()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public enableDiagnostics(Z)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/AssetLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/AssetLoader;->nEnableDiagnostics(JZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
