.class public Lcom/google/android/filament/gltfio/ResourceLoader;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final mNativeKtx2Provider:J

.field private final mNativeObject:J

.field private final mNativeStbProvider:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/Engine;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v0

    const/4 p1, 0x0

    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nCreateResourceLoader(JZ)J

    move-result-wide v2

    iput-wide v2, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 4
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nCreateStbProvider(J)J

    move-result-wide v4

    iput-wide v4, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeStbProvider:J

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nCreateKtx2Provider(J)J

    move-result-wide v0

    iput-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeKtx2Provider:J

    .line 6
    const-string p0, "image/jpeg"

    invoke-static {v2, v3, p0, v4, v5}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddTextureProvider(JLjava/lang/String;J)V

    .line 7
    const-string p0, "image/png"

    invoke-static {v2, v3, p0, v4, v5}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddTextureProvider(JLjava/lang/String;J)V

    .line 8
    const-string p0, "image/ktx2"

    invoke-static {v2, v3, p0, v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddTextureProvider(JLjava/lang/String;J)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/Engine;Z)V
    .locals 4

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v0

    .line 11
    invoke-static {v0, v1, p2}, Lcom/google/android/filament/gltfio/ResourceLoader;->nCreateResourceLoader(JZ)J

    move-result-wide p1

    iput-wide p1, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 12
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nCreateStbProvider(J)J

    move-result-wide v2

    iput-wide v2, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeStbProvider:J

    .line 13
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nCreateKtx2Provider(J)J

    move-result-wide v0

    iput-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeKtx2Provider:J

    .line 14
    const-string p0, "image/jpeg"

    invoke-static {p1, p2, p0, v2, v3}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddTextureProvider(JLjava/lang/String;J)V

    .line 15
    const-string p0, "image/png"

    invoke-static {p1, p2, p0, v2, v3}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddTextureProvider(JLjava/lang/String;J)V

    .line 16
    const-string p0, "image/ktx2"

    invoke-static {p1, p2, p0, v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddTextureProvider(JLjava/lang/String;J)V

    return-void
.end method

.method private static native nAddResourceData(JLjava/lang/String;Ljava/nio/Buffer;I)V
.end method

.method private static native nAddTextureProvider(JLjava/lang/String;J)V
.end method

.method private static native nAsyncBeginLoad(JJ)Z
.end method

.method private static native nAsyncCancelLoad(J)V
.end method

.method private static native nAsyncGetLoadProgress(J)F
.end method

.method private static native nAsyncUpdateLoad(J)V
.end method

.method private static native nCreateKtx2Provider(J)J
.end method

.method private static native nCreateResourceLoader(JZ)J
.end method

.method private static native nCreateStbProvider(J)J
.end method

.method private static native nDestroyResourceLoader(J)V
.end method

.method private static native nDestroyTextureProvider(J)V
.end method

.method private static native nEvictResourceData(J)V
.end method

.method private static native nHasResourceData(JLjava/lang/String;)Z
.end method

.method private static native nLoadResources(JJ)V
.end method


# virtual methods
.method public addResourceData(Ljava/lang/String;Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/ResourceLoader;
    .locals 3

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    invoke-static {v0, v1, p1, p2, v2}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAddResourceData(JLjava/lang/String;Ljava/nio/Buffer;I)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public asyncBeginLoad(Lcom/google/android/filament/gltfio/FilamentAsset;)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAsyncBeginLoad(JJ)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public asyncCancelLoad()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAsyncCancelLoad(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public asyncGetLoadProgress()F
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAsyncGetLoadProgress(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public asyncUpdateLoad()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nAsyncUpdateLoad(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public destroy()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nDestroyResourceLoader(J)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeStbProvider:J

    .line 7
    .line 8
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nDestroyTextureProvider(J)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeKtx2Provider:J

    .line 12
    .line 13
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nDestroyTextureProvider(J)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public evictResourceData()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nEvictResourceData(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public hasResourceData(Ljava/lang/String;)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/gltfio/ResourceLoader;->nHasResourceData(JLjava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public loadResources(Lcom/google/android/filament/gltfio/FilamentAsset;)Lcom/google/android/filament/gltfio/ResourceLoader;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/ResourceLoader;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/gltfio/ResourceLoader;->nLoadResources(JJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method
