.class public Lcom/google/android/filament/Engine;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Engine$Config;,
        Lcom/google/android/filament/Engine$Builder;,
        Lcom/google/android/filament/Engine$Backend;,
        Lcom/google/android/filament/Engine$FeatureLevel;,
        Lcom/google/android/filament/Engine$StereoscopicType;
    }
.end annotation


# static fields
.field private static final sBackendValues:[Lcom/google/android/filament/Engine$Backend;

.field private static final sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;


# instance fields
.field private mConfig:Lcom/google/android/filament/Engine$Config;

.field private final mEntityManager:Lcom/google/android/filament/EntityManager;

.field private final mLightManager:Lcom/google/android/filament/LightManager;

.field private mNativeObject:J

.field private final mRenderableManager:Lcom/google/android/filament/RenderableManager;

.field private final mTransformManager:Lcom/google/android/filament/TransformManager;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/Engine$Backend;->values()[Lcom/google/android/filament/Engine$Backend;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/Engine;->sBackendValues:[Lcom/google/android/filament/Engine$Backend;

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/filament/Engine$FeatureLevel;->values()[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/android/filament/Engine;->sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(JLcom/google/android/filament/Engine$Config;)V
    .locals 3

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lcom/google/android/filament/Engine;->mNativeObject:J

    .line 4
    new-instance v0, Lcom/google/android/filament/TransformManager;

    invoke-static {p1, p2}, Lcom/google/android/filament/Engine;->nGetTransformManager(J)J

    move-result-wide v1

    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/TransformManager;-><init>(J)V

    iput-object v0, p0, Lcom/google/android/filament/Engine;->mTransformManager:Lcom/google/android/filament/TransformManager;

    .line 5
    new-instance v0, Lcom/google/android/filament/LightManager;

    invoke-static {p1, p2}, Lcom/google/android/filament/Engine;->nGetLightManager(J)J

    move-result-wide v1

    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/LightManager;-><init>(J)V

    iput-object v0, p0, Lcom/google/android/filament/Engine;->mLightManager:Lcom/google/android/filament/LightManager;

    .line 6
    new-instance v0, Lcom/google/android/filament/RenderableManager;

    invoke-static {p1, p2}, Lcom/google/android/filament/Engine;->nGetRenderableManager(J)J

    move-result-wide v1

    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/RenderableManager;-><init>(J)V

    iput-object v0, p0, Lcom/google/android/filament/Engine;->mRenderableManager:Lcom/google/android/filament/RenderableManager;

    .line 7
    new-instance v0, Lcom/google/android/filament/EntityManager;

    invoke-static {p1, p2}, Lcom/google/android/filament/Engine;->nGetEntityManager(J)J

    move-result-wide p1

    invoke-direct {v0, p1, p2}, Lcom/google/android/filament/EntityManager;-><init>(J)V

    iput-object v0, p0, Lcom/google/android/filament/Engine;->mEntityManager:Lcom/google/android/filament/EntityManager;

    .line 8
    iput-object p3, p0, Lcom/google/android/filament/Engine;->mConfig:Lcom/google/android/filament/Engine$Config;

    return-void
.end method

.method public synthetic constructor <init>(JLcom/google/android/filament/Engine$Config;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/Engine;-><init>(JLcom/google/android/filament/Engine$Config;)V

    return-void
.end method

.method public static bridge synthetic a(J)J
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/Engine;->nBuilderBuild(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method private static assertDestroy(Z)V
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 5
    .line 6
    const-string v0, "Object couldn\'t be destroyed (double destroy()?)"

    .line 7
    .line 8
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public static bridge synthetic b()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/Engine;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic c(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/Engine;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Engine;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public static create()Lcom/google/android/filament/Engine;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/filament/Engine$Builder;

    invoke-direct {v0}, Lcom/google/android/filament/Engine$Builder;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/filament/Engine$Builder;->build()Lcom/google/android/filament/Engine;

    move-result-object v0

    return-object v0
.end method

.method public static create(Lcom/google/android/filament/Engine$Backend;)Lcom/google/android/filament/Engine;
    .locals 1

    .line 2
    new-instance v0, Lcom/google/android/filament/Engine$Builder;

    invoke-direct {v0}, Lcom/google/android/filament/Engine$Builder;-><init>()V

    .line 3
    invoke-virtual {v0, p0}, Lcom/google/android/filament/Engine$Builder;->backend(Lcom/google/android/filament/Engine$Backend;)Lcom/google/android/filament/Engine$Builder;

    move-result-object p0

    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/Engine$Builder;->build()Lcom/google/android/filament/Engine;

    move-result-object p0

    return-object p0
.end method

.method public static create(Ljava/lang/Object;)Lcom/google/android/filament/Engine;
    .locals 1

    .line 5
    new-instance v0, Lcom/google/android/filament/Engine$Builder;

    invoke-direct {v0}, Lcom/google/android/filament/Engine$Builder;-><init>()V

    .line 6
    invoke-virtual {v0, p0}, Lcom/google/android/filament/Engine$Builder;->sharedContext(Ljava/lang/Object;)Lcom/google/android/filament/Engine$Builder;

    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/Engine$Builder;->build()Lcom/google/android/filament/Engine;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic d(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Engine;->nSetBuilderBackend(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JJJJJJJZIJJJZIZZ)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p25}, Lcom/google/android/filament/Engine;->nSetBuilderConfig(JJJJJJJZIJJJZIZZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Engine;->nSetBuilderFeatureLevel(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/Engine;->nSetBuilderPaused(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static native getSteadyClockTimeNano()J
.end method

.method public static bridge synthetic h(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Engine;->nSetBuilderSharedContext(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(J)J
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nCreateCamera(JI)J
.end method

.method private static native nCreateFence(J)J
.end method

.method private static native nCreateRenderer(J)J
.end method

.method private static native nCreateScene(J)J
.end method

.method private static native nCreateSwapChain(JLjava/lang/Object;J)J
.end method

.method private static native nCreateSwapChainFromRawPointer(JJJ)J
.end method

.method private static native nCreateSwapChainHeadless(JIIJ)J
.end method

.method private static native nCreateView(J)J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nDestroyCameraComponent(JI)V
.end method

.method private static native nDestroyColorGrading(JJ)Z
.end method

.method private static native nDestroyEngine(J)V
.end method

.method private static native nDestroyEntity(JI)V
.end method

.method private static native nDestroyFence(JJ)Z
.end method

.method private static native nDestroyIndexBuffer(JJ)Z
.end method

.method private static native nDestroyIndirectLight(JJ)Z
.end method

.method private static native nDestroyMaterial(JJ)Z
.end method

.method private static native nDestroyMaterialInstance(JJ)Z
.end method

.method private static native nDestroyRenderTarget(JJ)Z
.end method

.method private static native nDestroyRenderer(JJ)Z
.end method

.method private static native nDestroyScene(JJ)Z
.end method

.method private static native nDestroySkinningBuffer(JJ)Z
.end method

.method private static native nDestroySkybox(JJ)Z
.end method

.method private static native nDestroyStream(JJ)Z
.end method

.method private static native nDestroySwapChain(JJ)Z
.end method

.method private static native nDestroyTexture(JJ)Z
.end method

.method private static native nDestroyVertexBuffer(JJ)Z
.end method

.method private static native nDestroyView(JJ)Z
.end method

.method private static native nFlush(J)V
.end method

.method private static native nFlushAndWait(J)V
.end method

.method private static native nGetActiveFeatureLevel(J)I
.end method

.method private static native nGetBackend(J)J
.end method

.method private static native nGetCameraComponent(JI)J
.end method

.method private static native nGetEntityManager(J)J
.end method

.method private static native nGetJobSystem(J)J
.end method

.method private static native nGetLightManager(J)J
.end method

.method private static native nGetMaxStereoscopicEyes(J)J
.end method

.method private static native nGetRenderableManager(J)J
.end method

.method private static native nGetSupportedFeatureLevel(J)I
.end method

.method private static native nGetTransformManager(J)J
.end method

.method private static native nIsAutomaticInstancingEnabled(J)Z
.end method

.method private static native nIsPaused(J)Z
.end method

.method private static native nIsValidColorGrading(JJ)Z
.end method

.method private static native nIsValidExpensiveMaterialInstance(JJ)Z
.end method

.method private static native nIsValidFence(JJ)Z
.end method

.method private static native nIsValidIndexBuffer(JJ)Z
.end method

.method private static native nIsValidIndirectLight(JJ)Z
.end method

.method private static native nIsValidMaterial(JJ)Z
.end method

.method private static native nIsValidMaterialInstance(JJJ)Z
.end method

.method private static native nIsValidRenderTarget(JJ)Z
.end method

.method private static native nIsValidRenderer(JJ)Z
.end method

.method private static native nIsValidScene(JJ)Z
.end method

.method private static native nIsValidSkinningBuffer(JJ)Z
.end method

.method private static native nIsValidSkybox(JJ)Z
.end method

.method private static native nIsValidStream(JJ)Z
.end method

.method private static native nIsValidSwapChain(JJ)Z
.end method

.method private static native nIsValidTexture(JJ)Z
.end method

.method private static native nIsValidVertexBuffer(JJ)Z
.end method

.method private static native nIsValidView(JJ)Z
.end method

.method private static native nSetActiveFeatureLevel(JI)I
.end method

.method private static native nSetAutomaticInstancingEnabled(JZ)V
.end method

.method private static native nSetBuilderBackend(JJ)V
.end method

.method private static native nSetBuilderConfig(JJJJJJJZIJJJZIZZ)V
.end method

.method private static native nSetBuilderFeatureLevel(JI)V
.end method

.method private static native nSetBuilderPaused(JZ)V
.end method

.method private static native nSetBuilderSharedContext(JJ)V
.end method

.method private static native nSetPaused(JZ)V
.end method

.method private static native nUnprotected(J)V
.end method


# virtual methods
.method public createCamera(I)Lcom/google/android/filament/Camera;
    .locals 4
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->nCreateCamera(JI)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    cmp-long p0, v0, v2

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    new-instance p0, Lcom/google/android/filament/Camera;

    .line 16
    .line 17
    invoke-direct {p0, v0, v1, p1}, Lcom/google/android/filament/Camera;-><init>(JI)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "Couldn\'t create Camera"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public createFence()Lcom/google/android/filament/Fence;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nCreateFence(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    cmp-long p0, v0, v2

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    new-instance p0, Lcom/google/android/filament/Fence;

    .line 16
    .line 17
    invoke-direct {p0, v0, v1}, Lcom/google/android/filament/Fence;-><init>(J)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v0, "Couldn\'t create Fence"

    .line 24
    .line 25
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public createRenderer()Lcom/google/android/filament/Renderer;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nCreateRenderer(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    cmp-long v2, v0, v2

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    new-instance v2, Lcom/google/android/filament/Renderer;

    .line 16
    .line 17
    invoke-direct {v2, p0, v0, v1}, Lcom/google/android/filament/Renderer;-><init>(Lcom/google/android/filament/Engine;J)V

    .line 18
    .line 19
    .line 20
    return-object v2

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v0, "Couldn\'t create Renderer"

    .line 24
    .line 25
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public createScene()Lcom/google/android/filament/Scene;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nCreateScene(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    cmp-long p0, v0, v2

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    new-instance p0, Lcom/google/android/filament/Scene;

    .line 16
    .line 17
    invoke-direct {p0, v0, v1}, Lcom/google/android/filament/Scene;-><init>(J)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v0, "Couldn\'t create Scene"

    .line 24
    .line 25
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public createSwapChain(IIJ)Lcom/google/android/filament/SwapChain;
    .locals 6

    if-ltz p1, :cond_1

    if-ltz p2, :cond_1

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v0

    move v2, p1

    move v3, p2

    move-wide v4, p3

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Engine;->nCreateSwapChainHeadless(JIIJ)J

    move-result-wide p0

    const-wide/16 p2, 0x0

    cmp-long p2, p0, p2

    if-eqz p2, :cond_0

    .line 14
    new-instance p2, Lcom/google/android/filament/SwapChain;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p1, p3}, Lcom/google/android/filament/SwapChain;-><init>(JLjava/lang/Object;)V

    return-object p2

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Couldn\'t create SwapChain"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 16
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Invalid parameters"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public createSwapChain(Ljava/lang/Object;)Lcom/google/android/filament/SwapChain;
    .locals 2

    const-wide/16 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, v0, v1}, Lcom/google/android/filament/Engine;->createSwapChain(Ljava/lang/Object;J)Lcom/google/android/filament/SwapChain;

    move-result-object p0

    return-object p0
.end method

.method public createSwapChain(Ljava/lang/Object;J)Lcom/google/android/filament/SwapChain;
    .locals 2

    .line 2
    invoke-static {}, Lcom/google/android/filament/Platform;->get()Lcom/google/android/filament/Platform;

    move-result-object v0

    invoke-virtual {v0, p1}, Lcom/google/android/filament/Platform;->validateSurface(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/Engine;->nCreateSwapChain(JLjava/lang/Object;J)J

    move-result-wide p2

    const-wide/16 v0, 0x0

    cmp-long p0, p2, v0

    if-eqz p0, :cond_0

    .line 4
    new-instance p0, Lcom/google/android/filament/SwapChain;

    invoke-direct {p0, p2, p3, p1}, Lcom/google/android/filament/SwapChain;-><init>(JLjava/lang/Object;)V

    return-object p0

    .line 5
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Couldn\'t create SwapChain"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 6
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p2, "Invalid surface "

    .line 7
    invoke-static {p1, p2}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 8
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public createSwapChainFromNativeSurface(Lcom/google/android/filament/NativeSurface;J)Lcom/google/android/filament/SwapChain;
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/NativeSurface;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    move-wide v4, p2

    .line 10
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Engine;->nCreateSwapChainFromRawPointer(JJJ)J

    .line 11
    .line 12
    .line 13
    move-result-wide p2

    .line 14
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    cmp-long p0, p2, v0

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    new-instance p0, Lcom/google/android/filament/SwapChain;

    .line 21
    .line 22
    invoke-direct {p0, p2, p3, p1}, Lcom/google/android/filament/SwapChain;-><init>(JLjava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "Couldn\'t create SwapChain"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public createView()Lcom/google/android/filament/View;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nCreateView(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    cmp-long p0, v0, v2

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    new-instance p0, Lcom/google/android/filament/View;

    .line 16
    .line 17
    invoke-direct {p0, v0, v1}, Lcom/google/android/filament/View;-><init>(J)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v0, "Couldn\'t create View"

    .line 24
    .line 25
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public destroy()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nDestroyEngine(J)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Lcom/google/android/filament/Engine;->clearNativeObject()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public destroyCameraComponent(I)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->nDestroyCameraComponent(JI)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public destroyColorGrading(Lcom/google/android/filament/ColorGrading;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/ColorGrading;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyColorGrading(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/ColorGrading;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyEntity(I)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->nDestroyEntity(JI)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public destroyFence(Lcom/google/android/filament/Fence;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Fence;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyFence(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Fence;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyIndexBuffer(Lcom/google/android/filament/IndexBuffer;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyIndexBuffer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/IndexBuffer;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyIndirectLight(Lcom/google/android/filament/IndirectLight;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyIndirectLight(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/IndirectLight;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyMaterial(Lcom/google/android/filament/Material;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyMaterial(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Material;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyMaterialInstance(Lcom/google/android/filament/MaterialInstance;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyMaterialInstance(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/MaterialInstance;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyRenderTarget(Lcom/google/android/filament/RenderTarget;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyRenderTarget(JJ)Z

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1}, Lcom/google/android/filament/RenderTarget;->clearNativeObject()V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public destroyRenderer(Lcom/google/android/filament/Renderer;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyRenderer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Renderer;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyScene(Lcom/google/android/filament/Scene;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyScene(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Scene;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroySkinningBuffer(Lcom/google/android/filament/SkinningBuffer;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/SkinningBuffer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroySkinningBuffer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/SkinningBuffer;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroySkybox(Lcom/google/android/filament/Skybox;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroySkybox(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Skybox;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyStream(Lcom/google/android/filament/Stream;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyStream(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Stream;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroySwapChain(Lcom/google/android/filament/SwapChain;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/SwapChain;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroySwapChain(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/SwapChain;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyTexture(Lcom/google/android/filament/Texture;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyTexture(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyVertexBuffer(Lcom/google/android/filament/VertexBuffer;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyVertexBuffer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/VertexBuffer;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public destroyView(Lcom/google/android/filament/View;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->nDestroyView(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/android/filament/Engine;->assertDestroy(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/View;->clearNativeObject()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public enableAccurateTranslations()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getTransformManager()Lcom/google/android/filament/TransformManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x1

    .line 6
    invoke-virtual {p0, v0}, Lcom/google/android/filament/TransformManager;->setAccurateTranslationsEnabled(Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public flush()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nFlush(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public flushAndWait()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nFlushAndWait(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public getActiveFeatureLevel()Lcom/google/android/filament/Engine$FeatureLevel;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Engine;->sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Engine;->nGetActiveFeatureLevel(J)I

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

.method public getBackend()Lcom/google/android/filament/Engine$Backend;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Engine;->sBackendValues:[Lcom/google/android/filament/Engine$Backend;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Engine;->nGetBackend(J)J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    long-to-int p0, v1

    .line 12
    aget-object p0, v0, p0

    .line 13
    .line 14
    return-object p0
.end method

.method public getCameraComponent(I)Lcom/google/android/filament/Camera;
    .locals 4
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->nGetCameraComponent(JI)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    cmp-long p0, v0, v2

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance p0, Lcom/google/android/filament/Camera;

    .line 18
    .line 19
    invoke-direct {p0, v0, v1, p1}, Lcom/google/android/filament/Camera;-><init>(JI)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public getConfig()Lcom/google/android/filament/Engine$Config;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/Engine;->mConfig:Lcom/google/android/filament/Engine$Config;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/Engine$Config;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/Engine$Config;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/Engine;->mConfig:Lcom/google/android/filament/Engine$Config;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/Engine;->mConfig:Lcom/google/android/filament/Engine$Config;

    .line 13
    .line 14
    return-object p0
.end method

.method public getEntityManager()Lcom/google/android/filament/EntityManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Engine;->mEntityManager:Lcom/google/android/filament/EntityManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public getLightManager()Lcom/google/android/filament/LightManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Engine;->mLightManager:Lcom/google/android/filament/LightManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMaxStereoscopicEyes()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nGetMaxStereoscopicEyes(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public getNativeJobSystem()J
    .locals 4
    .annotation build Lcom/google/android/filament/proguard/UsedByReflection;
        value = "MaterialBuilder.java"
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine;->mNativeObject:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nGetJobSystem(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    return-wide v0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string v0, "Calling method on destroyed Engine"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0
.end method

.method public getNativeObject()J
    .locals 4
    .annotation build Lcom/google/android/filament/proguard/UsedByReflection;
        value = "TextureHelper.java"
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed Engine"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getRenderableManager()Lcom/google/android/filament/RenderableManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Engine;->mRenderableManager:Lcom/google/android/filament/RenderableManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSupportedFeatureLevel()Lcom/google/android/filament/Engine$FeatureLevel;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Engine;->sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Engine;->nGetSupportedFeatureLevel(J)I

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

.method public getTransformManager()Lcom/google/android/filament/TransformManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Engine;->mTransformManager:Lcom/google/android/filament/TransformManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public isAutomaticInstancingEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nIsAutomaticInstancingEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isPaused()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nIsPaused(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isValid()Z
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine;->mNativeObject:J

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
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public isValidColorGrading(Lcom/google/android/filament/ColorGrading;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/ColorGrading;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidColorGrading(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidExpensiveMaterialInstance(Lcom/google/android/filament/MaterialInstance;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidExpensiveMaterialInstance(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidFence(Lcom/google/android/filament/Fence;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Fence;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidFence(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidIndexBuffer(Lcom/google/android/filament/IndexBuffer;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidIndexBuffer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidIndirectLight(Lcom/google/android/filament/IndirectLight;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidIndirectLight(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidMaterial(Lcom/google/android/filament/Material;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidMaterial(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidMaterialInstance(Lcom/google/android/filament/Material;Lcom/google/android/filament/MaterialInstance;)Z
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Material;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-virtual {p2}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 10
    .line 11
    .line 12
    move-result-wide v4

    .line 13
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Engine;->nIsValidMaterialInstance(JJJ)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public isValidRenderTarget(Lcom/google/android/filament/RenderTarget;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidRenderTarget(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidRenderer(Lcom/google/android/filament/Renderer;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidRenderer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidScene(Lcom/google/android/filament/Scene;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidScene(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidSkinningBuffer(Lcom/google/android/filament/SkinningBuffer;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/SkinningBuffer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidSkinningBuffer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidSkybox(Lcom/google/android/filament/Skybox;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidSkybox(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidStream(Lcom/google/android/filament/Stream;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidStream(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidSwapChain(Lcom/google/android/filament/SwapChain;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/SwapChain;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidSwapChain(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidTexture(Lcom/google/android/filament/Texture;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidTexture(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidVertexBuffer(Lcom/google/android/filament/VertexBuffer;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidVertexBuffer(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public isValidView(Lcom/google/android/filament/View;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Engine;->nIsValidView(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public setActiveFeatureLevel(Lcom/google/android/filament/Engine$FeatureLevel;)Lcom/google/android/filament/Engine$FeatureLevel;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Engine;->sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {v1, v2, p0}, Lcom/google/android/filament/Engine;->nSetActiveFeatureLevel(JI)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    aget-object p0, v0, p0

    .line 16
    .line 17
    return-object p0
.end method

.method public setAutomaticInstancingEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->nSetAutomaticInstancingEnabled(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setPaused(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->nSetPaused(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public unprotected()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->nUnprotected(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
