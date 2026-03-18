.class public Lcom/google/android/filament/LightManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/LightManager$Type;,
        Lcom/google/android/filament/LightManager$Builder;,
        Lcom/google/android/filament/LightManager$ShadowCascades;,
        Lcom/google/android/filament/LightManager$ShadowOptions;
    }
.end annotation


# static fields
.field public static final EFFICIENCY_FLUORESCENT:F = 0.0878f

.field public static final EFFICIENCY_HALOGEN:F = 0.0707f

.field public static final EFFICIENCY_INCANDESCENT:F = 0.022f

.field public static final EFFICIENCY_LED:F = 0.1171f

.field private static final sTypeValues:[Lcom/google/android/filament/LightManager$Type;


# instance fields
.field private mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/LightManager$Type;->values()[Lcom/google/android/filament/LightManager$Type;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/LightManager;->sTypeValues:[Lcom/google/android/filament/LightManager$Type;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method public static bridge synthetic a(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderAngularRadius(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(IJJ)Z
    .locals 0

    .line 1
    invoke-static {p1, p2, p3, p4, p0}, Lcom/google/android/filament/LightManager;->nBuilderBuild(JJI)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic c(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderCastLight(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderCastShadows(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/LightManager;->nBuilderColor(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/LightManager;->nBuilderDirection(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderFalloff(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic h(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderHaloFalloff(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderHaloSize(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic j(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderIntensity(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nBuilderIntensity(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic l(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/LightManager;->nBuilderIntensityCandela(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic m(JIZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nBuilderLightChannel(JIZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic n(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/LightManager;->nBuilderPosition(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderAngularRadius(JF)V
.end method

.method private static native nBuilderBuild(JJI)Z
.end method

.method private static native nBuilderCastLight(JZ)V
.end method

.method private static native nBuilderCastShadows(JZ)V
.end method

.method private static native nBuilderColor(JFFF)V
.end method

.method private static native nBuilderDirection(JFFF)V
.end method

.method private static native nBuilderFalloff(JF)V
.end method

.method private static native nBuilderHaloFalloff(JF)V
.end method

.method private static native nBuilderHaloSize(JF)V
.end method

.method private static native nBuilderIntensity(JF)V
.end method

.method private static native nBuilderIntensity(JFF)V
.end method

.method private static native nBuilderIntensityCandela(JF)V
.end method

.method private static native nBuilderLightChannel(JIZ)V
.end method

.method private static native nBuilderPosition(JFFF)V
.end method

.method private static native nBuilderShadowOptions(JII[FFFFFFZZFFZIFZFF[F)V
.end method

.method private static native nBuilderSpotLightCone(JFF)V
.end method

.method private static native nComputeLogSplits([FIFF)V
.end method

.method private static native nComputePracticalSplits([FIFFF)V
.end method

.method private static native nComputeUniformSplits([FI)V
.end method

.method private static native nCreateBuilder(I)J
.end method

.method private static native nDestroy(JI)V
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetColor(JI[F)V
.end method

.method private static native nGetComponentCount(J)I
.end method

.method private static native nGetDirection(JI[F)V
.end method

.method private static native nGetFalloff(JI)F
.end method

.method private static native nGetInnerConeAngle(JI)F
.end method

.method private static native nGetInstance(JI)I
.end method

.method private static native nGetIntensity(JI)F
.end method

.method private static native nGetLightChannel(JII)Z
.end method

.method private static native nGetOuterConeAngle(JI)F
.end method

.method private static native nGetPosition(JI[F)V
.end method

.method private static native nGetSunAngularRadius(JI)F
.end method

.method private static native nGetSunHaloFalloff(JI)F
.end method

.method private static native nGetSunHaloSize(JI)F
.end method

.method private static native nGetType(JI)I
.end method

.method private static native nHasComponent(JI)Z
.end method

.method private static native nIsShadowCaster(JI)Z
.end method

.method private static native nSetColor(JIFFF)V
.end method

.method private static native nSetDirection(JIFFF)V
.end method

.method private static native nSetFalloff(JIF)V
.end method

.method private static native nSetIntensity(JIF)V
.end method

.method private static native nSetIntensity(JIFF)V
.end method

.method private static native nSetIntensityCandela(JIF)V
.end method

.method private static native nSetLightChannel(JIIZ)V
.end method

.method private static native nSetPosition(JIFFF)V
.end method

.method private static native nSetShadowCaster(JIZ)V
.end method

.method private static native nSetSpotLightCone(JIFF)V
.end method

.method private static native nSetSunAngularRadius(JIF)V
.end method

.method private static native nSetSunHaloFalloff(JIF)V
.end method

.method private static native nSetSunHaloSize(JIF)V
.end method

.method public static bridge synthetic o(JII[FFFFFFZZFFZIFZFF[F)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p20}, Lcom/google/android/filament/LightManager;->nBuilderShadowOptions(JII[FFFFFFZZFFZIFZFF[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic p(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nBuilderSpotLightCone(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic q([FIFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nComputeLogSplits([FIFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic r([FIFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/LightManager;->nComputePracticalSplits([FIFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic s([FI)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/LightManager;->nComputeUniformSplits([FI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic t(I)J
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/LightManager;->nCreateBuilder(I)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic u(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/LightManager;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public destroy(I)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nDestroy(JI)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getColor(I[F)[F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat3([F)[F

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 6
    .line 7
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nGetColor(JI[F)V

    .line 8
    .line 9
    .line 10
    return-object p2
.end method

.method public getComponentCount()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/LightManager;->nGetComponentCount(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getDirection(I[F)[F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat3([F)[F

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 6
    .line 7
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nGetDirection(JI[F)V

    .line 8
    .line 9
    .line 10
    return-object p2
.end method

.method public getFalloff(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetFalloff(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getInnerConeAngle(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetInnerConeAngle(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getInstance(I)I
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param
    .annotation build Lcom/google/android/filament/EntityInstance;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetInstance(JI)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getIntensity(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetIntensity(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getLightChannel(II)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nGetLightChannel(JII)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getNativeObject()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getOuterConeAngle(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetOuterConeAngle(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getPosition(I[F)[F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat3([F)[F

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 6
    .line 7
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nGetPosition(JI[F)V

    .line 8
    .line 9
    .line 10
    return-object p2
.end method

.method public getSunAngularRadius(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetSunAngularRadius(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getSunHaloFalloff(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetSunHaloFalloff(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getSunHaloSize(I)F
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nGetSunHaloSize(JI)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getType(I)Lcom/google/android/filament/LightManager$Type;
    .locals 3
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    sget-object v0, Lcom/google/android/filament/LightManager;->sTypeValues:[Lcom/google/android/filament/LightManager$Type;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 4
    .line 5
    invoke-static {v1, v2, p1}, Lcom/google/android/filament/LightManager;->nGetType(JI)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public hasComponent(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nHasComponent(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public isDirectional(I)Z
    .locals 0
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/LightManager;->getType(I)Lcom/google/android/filament/LightManager$Type;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object p1, Lcom/google/android/filament/LightManager$Type;->DIRECTIONAL:Lcom/google/android/filament/LightManager$Type;

    .line 6
    .line 7
    if-eq p0, p1, :cond_1

    .line 8
    .line 9
    sget-object p1, Lcom/google/android/filament/LightManager$Type;->SUN:Lcom/google/android/filament/LightManager$Type;

    .line 10
    .line 11
    if-ne p0, p1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public isPointLight(I)Z
    .locals 0
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/LightManager;->getType(I)Lcom/google/android/filament/LightManager$Type;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object p1, Lcom/google/android/filament/LightManager$Type;->POINT:Lcom/google/android/filament/LightManager$Type;

    .line 6
    .line 7
    if-ne p0, p1, :cond_0

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

.method public isShadowCaster(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->nIsShadowCaster(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public isSpotLight(I)Z
    .locals 0
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/LightManager;->getType(I)Lcom/google/android/filament/LightManager$Type;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object p1, Lcom/google/android/filament/LightManager$Type;->SPOT:Lcom/google/android/filament/LightManager$Type;

    .line 6
    .line 7
    if-eq p0, p1, :cond_1

    .line 8
    .line 9
    sget-object p1, Lcom/google/android/filament/LightManager$Type;->FOCUSED_SPOT:Lcom/google/android/filament/LightManager$Type;

    .line 10
    .line 11
    if-ne p0, p1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public setColor(IFFF)V
    .locals 6
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    move v2, p1

    .line 4
    move v3, p2

    .line 5
    move v4, p3

    .line 6
    move v5, p4

    .line 7
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/LightManager;->nSetColor(JIFFF)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setDirection(IFFF)V
    .locals 6
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    move v2, p1

    .line 4
    move v3, p2

    .line 5
    move v4, p3

    .line 6
    move v5, p4

    .line 7
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/LightManager;->nSetDirection(JIFFF)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setFalloff(IF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetFalloff(JIF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setIntensity(IF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetIntensity(JIF)V

    return-void
.end method

.method public setIntensity(IFF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nSetIntensity(JIFF)V

    return-void
.end method

.method public setIntensityCandela(IF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetIntensityCandela(JIF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setLightChannel(IIZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nSetLightChannel(JIIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setPosition(IFFF)V
    .locals 6
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    move v2, p1

    .line 4
    move v3, p2

    .line 5
    move v4, p3

    .line 6
    move v5, p4

    .line 7
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/LightManager;->nSetPosition(JIFFF)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setShadowCaster(IZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetShadowCaster(JIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setSpotLightCone(IFF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/LightManager;->nSetSpotLightCone(JIFF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setSunAngularRadius(IF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetSunAngularRadius(JIF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setSunHaloFalloff(IF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetSunHaloFalloff(JIF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setSunHaloSize(IF)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->nSetSunHaloSize(JIF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
