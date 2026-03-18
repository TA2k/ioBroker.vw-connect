.class public Lcom/google/android/filament/gltfio/UbershaderProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/filament/gltfio/MaterialProvider;


# static fields
.field private static final sVertexAttributesValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;


# instance fields
.field private mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->values()[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/gltfio/UbershaderProvider;->sVertexAttributesValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/Engine;)V
    .locals 2

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
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nCreateUbershaderProvider(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 13
    .line 14
    return-void
.end method

.method private static native nCreateMaterialInstance(JLcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;Ljava/lang/String;)J
.end method

.method private static native nCreateUbershaderProvider(J)J
.end method

.method private static native nDestroyMaterials(J)V
.end method

.method private static native nDestroyUbershaderProvider(J)V
.end method

.method private static native nGetMaterial(JLcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;)J
.end method

.method private static native nGetMaterialCount(J)I
.end method

.method private static native nGetMaterials(J[J)V
.end method


# virtual methods
.method public createMaterialInstance(Lcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;Ljava/lang/String;)Lcom/google/android/filament/MaterialInstance;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 2
    .line 3
    move-object v2, p1

    .line 4
    move-object v3, p2

    .line 5
    move-object v4, p3

    .line 6
    move-object v5, p4

    .line 7
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nCreateMaterialInstance(JLcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;Ljava/lang/String;)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    const-wide/16 p2, 0x0

    .line 12
    .line 13
    cmp-long p2, p0, p2

    .line 14
    .line 15
    const/4 p3, 0x0

    .line 16
    if-nez p2, :cond_0

    .line 17
    .line 18
    return-object p3

    .line 19
    :cond_0
    new-instance p2, Lcom/google/android/filament/MaterialInstance;

    .line 20
    .line 21
    invoke-direct {p2, p3, p0, p1}, Lcom/google/android/filament/MaterialInstance;-><init>(Lcom/google/android/filament/Engine;J)V

    .line 22
    .line 23
    .line 24
    return-object p2
.end method

.method public destroy()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nDestroyUbershaderProvider(J)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 9
    .line 10
    return-void
.end method

.method public destroyMaterials()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nDestroyMaterials(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getMaterial(Lcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;)Lcom/google/android/filament/Material;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nGetMaterial(JLcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    const-wide/16 p2, 0x0

    .line 8
    .line 9
    cmp-long p2, p0, p2

    .line 10
    .line 11
    if-nez p2, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return-object p0

    .line 15
    :cond_0
    new-instance p2, Lcom/google/android/filament/Material;

    .line 16
    .line 17
    invoke-direct {p2, p0, p1}, Lcom/google/android/filament/Material;-><init>(J)V

    .line 18
    .line 19
    .line 20
    return-object p2
.end method

.method public getMaterials()[Lcom/google/android/filament/Material;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nGetMaterialCount(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-array v1, v0, [Lcom/google/android/filament/Material;

    .line 8
    .line 9
    new-array v2, v0, [J

    .line 10
    .line 11
    iget-wide v3, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 12
    .line 13
    invoke-static {v3, v4, v2}, Lcom/google/android/filament/gltfio/UbershaderProvider;->nGetMaterials(J[J)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    :goto_0
    if-ge p0, v0, :cond_0

    .line 18
    .line 19
    new-instance v3, Lcom/google/android/filament/Material;

    .line 20
    .line 21
    aget-wide v4, v2, p0

    .line 22
    .line 23
    invoke-direct {v3, v4, v5}, Lcom/google/android/filament/Material;-><init>(J)V

    .line 24
    .line 25
    .line 26
    aput-object v3, v1, p0

    .line 27
    .line 28
    add-int/lit8 p0, p0, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-object v1
.end method

.method public getNativeObject()J
    .locals 2
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "AssetLoader.cpp"
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public needsDummyData(I)Z
    .locals 1

    .line 1
    sget-object p0, Lcom/google/android/filament/gltfio/UbershaderProvider;->sVertexAttributesValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    sget-object p1, Lcom/google/android/filament/gltfio/UbershaderProvider$1;->$SwitchMap$com$google$android$filament$VertexBuffer$VertexAttribute:[I

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget p0, p1, p0

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    if-eq p0, p1, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-eq p0, v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    if-eq p0, v0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_0
    return p1
.end method
