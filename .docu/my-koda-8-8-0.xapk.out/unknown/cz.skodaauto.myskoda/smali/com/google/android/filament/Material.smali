.class public Lcom/google/android/filament/Material;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "AssetLoader.cpp"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Material$CompilerPriorityQueue;,
        Lcom/google/android/filament/Material$EnumCache;,
        Lcom/google/android/filament/Material$Shading;,
        Lcom/google/android/filament/Material$Interpolation;,
        Lcom/google/android/filament/Material$BlendingMode;,
        Lcom/google/android/filament/Material$RefractionMode;,
        Lcom/google/android/filament/Material$RefractionType;,
        Lcom/google/android/filament/Material$ReflectionMode;,
        Lcom/google/android/filament/Material$VertexDomain;,
        Lcom/google/android/filament/Material$CullingMode;,
        Lcom/google/android/filament/Material$Builder;,
        Lcom/google/android/filament/Material$Parameter;,
        Lcom/google/android/filament/Material$UserVariantFilterBit;
    }
.end annotation


# instance fields
.field private final mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

.field private mNativeObject:J

.field private mRequiredAttributes:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/google/android/filament/VertexBuffer$VertexAttribute;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/Material;->mNativeObject:J

    .line 5
    .line 6
    invoke-static {p1, p2}, Lcom/google/android/filament/Material;->nGetDefaultInstance(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p1

    .line 10
    new-instance v0, Lcom/google/android/filament/MaterialInstance;

    .line 11
    .line 12
    invoke-direct {v0, p0, p1, p2}, Lcom/google/android/filament/MaterialInstance;-><init>(Lcom/google/android/filament/Material;J)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    .line 16
    .line 17
    return-void
.end method

.method public static bridge synthetic a(JILjava/nio/Buffer;I)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p3, p2, p4}, Lcom/google/android/filament/Material;->nBuilderBuild(JLjava/nio/Buffer;II)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method private static native nBuilderBuild(JLjava/nio/Buffer;II)J
.end method

.method private static native nCompile(JIILjava/lang/Object;Ljava/lang/Runnable;)V
.end method

.method private static native nCreateInstance(J)J
.end method

.method private static native nCreateInstanceWithName(JLjava/lang/String;)J
.end method

.method private static native nGetBlendingMode(J)I
.end method

.method private static native nGetCullingMode(J)I
.end method

.method private static native nGetDefaultInstance(J)J
.end method

.method private static native nGetFeatureLevel(J)I
.end method

.method private static native nGetInterpolation(J)I
.end method

.method private static native nGetMaskThreshold(J)F
.end method

.method private static native nGetName(J)Ljava/lang/String;
.end method

.method private static native nGetParameterCount(J)I
.end method

.method private static native nGetParameters(JLjava/util/List;I)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Ljava/util/List<",
            "Lcom/google/android/filament/Material$Parameter;",
            ">;I)V"
        }
    .end annotation
.end method

.method private static native nGetReflectionMode(J)I
.end method

.method private static native nGetRefractionMode(J)I
.end method

.method private static native nGetRefractionType(J)I
.end method

.method private static native nGetRequiredAttributes(J)I
.end method

.method private static native nGetShading(J)I
.end method

.method private static native nGetSpecularAntiAliasingThreshold(J)F
.end method

.method private static native nGetSpecularAntiAliasingVariance(J)F
.end method

.method private static native nGetVertexDomain(J)I
.end method

.method private static native nHasParameter(JLjava/lang/String;)Z
.end method

.method private static native nIsAlphaToCoverageEnabled(J)Z
.end method

.method private static native nIsColorWriteEnabled(J)Z
.end method

.method private static native nIsDepthCullingEnabled(J)Z
.end method

.method private static native nIsDepthWriteEnabled(J)Z
.end method

.method private static native nIsDoubleSided(J)Z
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Material;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public compile(Lcom/google/android/filament/Material$CompilerPriorityQueue;ILjava/lang/Object;Ljava/lang/Runnable;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    move v3, p2

    .line 10
    move-object v4, p3

    .line 11
    move-object v5, p4

    .line 12
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Material;->nCompile(JIILjava/lang/Object;Ljava/lang/Runnable;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public createInstance()Lcom/google/android/filament/MaterialInstance;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nCreateInstance(J)J

    move-result-wide v0

    const-wide/16 v2, 0x0

    cmp-long v2, v0, v2

    if-eqz v2, :cond_0

    .line 2
    new-instance v2, Lcom/google/android/filament/MaterialInstance;

    invoke-direct {v2, p0, v0, v1}, Lcom/google/android/filament/MaterialInstance;-><init>(Lcom/google/android/filament/Material;J)V

    return-object v2

    .line 3
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "Couldn\'t create MaterialInstance"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public createInstance(Ljava/lang/String;)Lcom/google/android/filament/MaterialInstance;
    .locals 4

    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Material;->nCreateInstanceWithName(JLjava/lang/String;)J

    move-result-wide v0

    const-wide/16 v2, 0x0

    cmp-long p1, v0, v2

    if-eqz p1, :cond_0

    .line 5
    new-instance p1, Lcom/google/android/filament/MaterialInstance;

    invoke-direct {p1, p0, v0, v1}, Lcom/google/android/filament/MaterialInstance;-><init>(Lcom/google/android/filament/Material;J)V

    return-object p1

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Couldn\'t create MaterialInstance"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public getBlendingMode()Lcom/google/android/filament/Material$BlendingMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sBlendingModeValues:[Lcom/google/android/filament/Material$BlendingMode;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetBlendingMode(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getCullingMode()Lcom/google/android/filament/Material$CullingMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sCullingModeValues:[Lcom/google/android/filament/Material$CullingMode;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetCullingMode(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getDefaultInstance()Lcom/google/android/filament/MaterialInstance;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    .line 2
    .line 3
    return-object p0
.end method

.method public getFeatureLevel()Lcom/google/android/filament/Engine$FeatureLevel;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetFeatureLevel(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getInterpolation()Lcom/google/android/filament/Material$Interpolation;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sInterpolationValues:[Lcom/google/android/filament/Material$Interpolation;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetInterpolation(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getMaskThreshold()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetMaskThreshold(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getName()Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetName(J)Ljava/lang/String;

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
    iget-wide v0, p0, Lcom/google/android/filament/Material;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed Material"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getParameterCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetParameterCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getParameters()Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/google/android/filament/Material$Parameter;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getParameterCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-instance v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    if-lez v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    invoke-static {v2, v3, v1, v0}, Lcom/google/android/filament/Material;->nGetParameters(JLjava/util/List;I)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-object v1
.end method

.method public getReflectionMode()Lcom/google/android/filament/Material$ReflectionMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sReflectionModeValues:[Lcom/google/android/filament/Material$ReflectionMode;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetReflectionMode(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getRefractionMode()Lcom/google/android/filament/Material$RefractionMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sRefractionModeValues:[Lcom/google/android/filament/Material$RefractionMode;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetRefractionMode(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getRefractionType()Lcom/google/android/filament/Material$RefractionType;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sRefractionTypeValues:[Lcom/google/android/filament/Material$RefractionType;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetRefractionType(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getRequiredAttributes()Ljava/util/Set;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lcom/google/android/filament/VertexBuffer$VertexAttribute;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/Material;->mRequiredAttributes:Ljava/util/Set;

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetRequiredAttributes(J)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const-class v1, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 14
    .line 15
    invoke-static {v1}, Ljava/util/EnumSet;->noneOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    iput-object v1, p0, Lcom/google/android/filament/Material;->mRequiredAttributes:Ljava/util/Set;

    .line 20
    .line 21
    sget-object v1, Lcom/google/android/filament/Material$EnumCache;->sVertexAttributeValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    :goto_0
    array-length v3, v1

    .line 25
    if-ge v2, v3, :cond_1

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    shl-int/2addr v3, v2

    .line 29
    and-int/2addr v3, v0

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    iget-object v3, p0, Lcom/google/android/filament/Material;->mRequiredAttributes:Ljava/util/Set;

    .line 33
    .line 34
    aget-object v4, v1, v2

    .line 35
    .line 36
    invoke-interface {v3, v4}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    iget-object v0, p0, Lcom/google/android/filament/Material;->mRequiredAttributes:Ljava/util/Set;

    .line 43
    .line 44
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iput-object v0, p0, Lcom/google/android/filament/Material;->mRequiredAttributes:Ljava/util/Set;

    .line 49
    .line 50
    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/Material;->mRequiredAttributes:Ljava/util/Set;

    .line 51
    .line 52
    return-object p0
.end method

.method public getRequiredAttributesAsInt()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetRequiredAttributes(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getShading()Lcom/google/android/filament/Material$Shading;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sShadingValues:[Lcom/google/android/filament/Material$Shading;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetShading(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getSpecularAntiAliasingThreshold()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetSpecularAntiAliasingThreshold(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getSpecularAntiAliasingVariance()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nGetSpecularAntiAliasingVariance(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getVertexDomain()Lcom/google/android/filament/Material$VertexDomain;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$EnumCache;->sVertexDomainValues:[Lcom/google/android/filament/Material$VertexDomain;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Material;->nGetVertexDomain(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public hasParameter(Ljava/lang/String;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Material;->nHasParameter(JLjava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isAlphaToCoverageEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nIsAlphaToCoverageEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isColorWriteEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nIsColorWriteEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isDepthCullingEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nIsDepthCullingEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isDepthWriteEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nIsDepthWriteEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isDoubleSided()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Material;->nIsDoubleSided(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public setDefaultParameter(Ljava/lang/String;F)V
    .locals 0

    .line 2
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;F)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;FF)V
    .locals 0

    .line 5
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;FF)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;FFF)V
    .locals 0

    .line 8
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;FFF)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;FFFF)V
    .locals 0

    .line 11
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;FFFF)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;I)V
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;I)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;II)V
    .locals 0

    .line 6
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;II)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;III)V
    .locals 0

    .line 9
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;III)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;IIII)V
    .locals 0

    .line 12
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;IIII)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Lcom/google/android/filament/Colors$RgbType;FFF)V
    .locals 0

    .line 16
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Lcom/google/android/filament/Colors$RgbType;FFF)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Lcom/google/android/filament/Colors$RgbaType;FFFF)V
    .locals 0

    .line 17
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p6}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Lcom/google/android/filament/Colors$RgbaType;FFFF)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$BooleanElement;[ZII)V
    .locals 0

    .line 13
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$BooleanElement;[ZII)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$FloatElement;[FII)V
    .locals 0

    .line 15
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$FloatElement;[FII)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$IntElement;[III)V
    .locals 0

    .line 14
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$IntElement;[III)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Lcom/google/android/filament/Texture;Lcom/google/android/filament/TextureSampler;)V
    .locals 0

    .line 18
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Lcom/google/android/filament/Texture;Lcom/google/android/filament/TextureSampler;)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;Z)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;ZZ)V
    .locals 0

    .line 4
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;ZZ)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;ZZZ)V
    .locals 0

    .line 7
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;ZZZ)V

    return-void
.end method

.method public setDefaultParameter(Ljava/lang/String;ZZZZ)V
    .locals 0

    .line 10
    iget-object p0, p0, Lcom/google/android/filament/Material;->mDefaultInstance:Lcom/google/android/filament/MaterialInstance;

    invoke-virtual/range {p0 .. p5}, Lcom/google/android/filament/MaterialInstance;->setParameter(Ljava/lang/String;ZZZZ)V

    return-void
.end method
