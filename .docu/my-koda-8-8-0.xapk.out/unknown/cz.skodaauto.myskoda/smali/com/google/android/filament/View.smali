.class public Lcom/google/android/filament/View;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/View$BlendMode;,
        Lcom/google/android/filament/View$AntiAliasing;,
        Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;,
        Lcom/google/android/filament/View$TemporalAntiAliasingOptions;,
        Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;,
        Lcom/google/android/filament/View$GuardBandOptions;,
        Lcom/google/android/filament/View$ToneMapping;,
        Lcom/google/android/filament/View$Dithering;,
        Lcom/google/android/filament/View$DynamicResolutionOptions;,
        Lcom/google/android/filament/View$QualityLevel;,
        Lcom/google/android/filament/View$RenderQuality;,
        Lcom/google/android/filament/View$ShadowType;,
        Lcom/google/android/filament/View$VsmShadowOptions;,
        Lcom/google/android/filament/View$SoftShadowOptions;,
        Lcom/google/android/filament/View$AmbientOcclusion;,
        Lcom/google/android/filament/View$AmbientOcclusionOptions;,
        Lcom/google/android/filament/View$BloomOptions;,
        Lcom/google/android/filament/View$VignetteOptions;,
        Lcom/google/android/filament/View$FogOptions;,
        Lcom/google/android/filament/View$DepthOfFieldOptions;,
        Lcom/google/android/filament/View$StereoscopicOptions;,
        Lcom/google/android/filament/View$InternalOnPickCallback;,
        Lcom/google/android/filament/View$OnPickCallback;,
        Lcom/google/android/filament/View$PickingQueryResult;,
        Lcom/google/android/filament/View$TargetBufferFlags;
    }
.end annotation


# static fields
.field private static final sAmbientOcclusionValues:[Lcom/google/android/filament/View$AmbientOcclusion;

.field private static final sAntiAliasingValues:[Lcom/google/android/filament/View$AntiAliasing;

.field private static final sDitheringValues:[Lcom/google/android/filament/View$Dithering;


# instance fields
.field private mAmbientOcclusionOptions:Lcom/google/android/filament/View$AmbientOcclusionOptions;

.field private mBlendMode:Lcom/google/android/filament/View$BlendMode;

.field private mBloomOptions:Lcom/google/android/filament/View$BloomOptions;

.field private mCamera:Lcom/google/android/filament/Camera;

.field private mColorGrading:Lcom/google/android/filament/ColorGrading;

.field private mDepthOfFieldOptions:Lcom/google/android/filament/View$DepthOfFieldOptions;

.field private mDynamicResolution:Lcom/google/android/filament/View$DynamicResolutionOptions;

.field private mFogOptions:Lcom/google/android/filament/View$FogOptions;

.field private mGuardBandOptions:Lcom/google/android/filament/View$GuardBandOptions;

.field private mMultiSampleAntiAliasingOptions:Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;

.field private mName:Ljava/lang/String;

.field private mNativeObject:J

.field private mRenderQuality:Lcom/google/android/filament/View$RenderQuality;

.field private mRenderTarget:Lcom/google/android/filament/RenderTarget;

.field private mScene:Lcom/google/android/filament/Scene;

.field private mScreenSpaceReflectionsOptions:Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;

.field private mSoftShadowOptions:Lcom/google/android/filament/View$SoftShadowOptions;

.field private mStereoscopicOptions:Lcom/google/android/filament/View$StereoscopicOptions;

.field private mTemporalAntiAliasingOptions:Lcom/google/android/filament/View$TemporalAntiAliasingOptions;

.field private mViewport:Lcom/google/android/filament/Viewport;

.field private mVignetteOptions:Lcom/google/android/filament/View$VignetteOptions;

.field private mVsmShadowOptions:Lcom/google/android/filament/View$VsmShadowOptions;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/View$AntiAliasing;->values()[Lcom/google/android/filament/View$AntiAliasing;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/View;->sAntiAliasingValues:[Lcom/google/android/filament/View$AntiAliasing;

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/filament/View$Dithering;->values()[Lcom/google/android/filament/View$Dithering;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/android/filament/View;->sDitheringValues:[Lcom/google/android/filament/View$Dithering;

    .line 12
    .line 13
    invoke-static {}, Lcom/google/android/filament/View$AmbientOcclusion;->values()[Lcom/google/android/filament/View$AmbientOcclusion;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lcom/google/android/filament/View;->sAmbientOcclusionValues:[Lcom/google/android/filament/View$AmbientOcclusion;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(J)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/android/filament/Viewport;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v1, v1}, Lcom/google/android/filament/Viewport;-><init>(IIII)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mViewport:Lcom/google/android/filament/Viewport;

    .line 11
    .line 12
    iput-wide p1, p0, Lcom/google/android/filament/View;->mNativeObject:J

    .line 13
    .line 14
    return-void
.end method

.method private static native nClearFrameHistory(JJ)V
.end method

.method private static native nGetAmbientOcclusion(J)I
.end method

.method private static native nGetAntiAliasing(J)I
.end method

.method private static native nGetDithering(J)I
.end method

.method private static native nGetFogEntity(J)I
.end method

.method private static native nGetMaterialGlobal(JI[F)V
.end method

.method private static native nGetSampleCount(J)I
.end method

.method private static native nHasCamera(J)Z
.end method

.method private static native nIsFrontFaceWindingInverted(J)Z
.end method

.method private static native nIsPostProcessingEnabled(J)Z
.end method

.method private static native nIsScreenSpaceRefractionEnabled(J)Z
.end method

.method private static native nIsShadowingEnabled(J)Z
.end method

.method private static native nIsStencilBufferEnabled(J)Z
.end method

.method private static native nIsTransparentPickingEnabled(J)Z
.end method

.method private static native nPick(JIILjava/lang/Object;Lcom/google/android/filament/View$InternalOnPickCallback;)V
.end method

.method private static native nSetAmbientOcclusion(JI)V
.end method

.method private static native nSetAmbientOcclusionOptions(JFFFFFFIIIZZF)V
.end method

.method private static native nSetAntiAliasing(JI)V
.end method

.method private static native nSetBlendMode(JI)V
.end method

.method private static native nSetBloomOptions(JJFFIIIZZFZZFIFFFFF)V
.end method

.method private static native nSetCamera(JJ)V
.end method

.method private static native nSetColorGrading(JJ)V
.end method

.method private static native nSetDepthOfFieldOptions(JFFZIZIIIII)V
.end method

.method private static native nSetDithering(JI)V
.end method

.method private static native nSetDynamicLightingOptions(JFF)V
.end method

.method private static native nSetDynamicResolutionOptions(JZZFFFI)V
.end method

.method private static native nSetFogOptions(JFFFFFFFFFFFZJZ)V
.end method

.method private static native nSetFrontFaceWindingInverted(JZ)V
.end method

.method private static native nSetGuardBandOptions(JZ)V
.end method

.method private static native nSetMaterialGlobal(JIFFFF)V
.end method

.method private static native nSetMultiSampleAntiAliasingOptions(JZIZ)V
.end method

.method private static native nSetName(JLjava/lang/String;)V
.end method

.method private static native nSetPostProcessingEnabled(JZ)V
.end method

.method private static native nSetRenderQuality(JI)V
.end method

.method private static native nSetRenderTarget(JJ)V
.end method

.method private static native nSetSSCTOptions(JFFFFFFFFFIIZ)V
.end method

.method private static native nSetSampleCount(JI)V
.end method

.method private static native nSetScene(JJ)V
.end method

.method private static native nSetScreenSpaceReflectionsOptions(JFFFFZ)V
.end method

.method private static native nSetScreenSpaceRefractionEnabled(JZ)V
.end method

.method private static native nSetShadowType(JI)V
.end method

.method private static native nSetShadowingEnabled(JZ)V
.end method

.method private static native nSetSoftShadowOptions(JFF)V
.end method

.method private static native nSetStencilBufferEnabled(JZ)V
.end method

.method private static native nSetStereoscopicOptions(JZ)V
.end method

.method private static native nSetTemporalAntiAliasingOptions(JFFZ)V
.end method

.method private static native nSetTransparentPickingEnabled(JZ)V
.end method

.method private static native nSetViewport(JIIII)V
.end method

.method private static native nSetVignetteOptions(JFFFFFFFZ)V
.end method

.method private static native nSetVisibleLayers(JII)V
.end method

.method private static native nSetVsmShadowOptions(JIZZFF)V
.end method


# virtual methods
.method public clearFrameHistory(Lcom/google/android/filament/Engine;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/View;->nClearFrameHistory(JJ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/View;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getAmbientOcclusion()Lcom/google/android/filament/View$AmbientOcclusion;
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    sget-object v0, Lcom/google/android/filament/View;->sAmbientOcclusionValues:[Lcom/google/android/filament/View$AmbientOcclusion;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/View;->nGetAmbientOcclusion(J)I

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

.method public getAmbientOcclusionOptions()Lcom/google/android/filament/View$AmbientOcclusionOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mAmbientOcclusionOptions:Lcom/google/android/filament/View$AmbientOcclusionOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$AmbientOcclusionOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$AmbientOcclusionOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mAmbientOcclusionOptions:Lcom/google/android/filament/View$AmbientOcclusionOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mAmbientOcclusionOptions:Lcom/google/android/filament/View$AmbientOcclusionOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getAntiAliasing()Lcom/google/android/filament/View$AntiAliasing;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/View;->sAntiAliasingValues:[Lcom/google/android/filament/View$AntiAliasing;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/View;->nGetAntiAliasing(J)I

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

.method public getBlendMode()Lcom/google/android/filament/View$BlendMode;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mBlendMode:Lcom/google/android/filament/View$BlendMode;

    .line 2
    .line 3
    return-object p0
.end method

.method public getBloomOptions()Lcom/google/android/filament/View$BloomOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mBloomOptions:Lcom/google/android/filament/View$BloomOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$BloomOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$BloomOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mBloomOptions:Lcom/google/android/filament/View$BloomOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mBloomOptions:Lcom/google/android/filament/View$BloomOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getCamera()Lcom/google/android/filament/Camera;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mCamera:Lcom/google/android/filament/Camera;

    .line 2
    .line 3
    return-object p0
.end method

.method public getColorGrading()Lcom/google/android/filament/ColorGrading;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mColorGrading:Lcom/google/android/filament/ColorGrading;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDepthOfFieldOptions()Lcom/google/android/filament/View$DepthOfFieldOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mDepthOfFieldOptions:Lcom/google/android/filament/View$DepthOfFieldOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$DepthOfFieldOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$DepthOfFieldOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mDepthOfFieldOptions:Lcom/google/android/filament/View$DepthOfFieldOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mDepthOfFieldOptions:Lcom/google/android/filament/View$DepthOfFieldOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getDithering()Lcom/google/android/filament/View$Dithering;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/View;->sDitheringValues:[Lcom/google/android/filament/View$Dithering;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/View;->nGetDithering(J)I

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

.method public getDynamicResolutionOptions()Lcom/google/android/filament/View$DynamicResolutionOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mDynamicResolution:Lcom/google/android/filament/View$DynamicResolutionOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$DynamicResolutionOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$DynamicResolutionOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mDynamicResolution:Lcom/google/android/filament/View$DynamicResolutionOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mDynamicResolution:Lcom/google/android/filament/View$DynamicResolutionOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getFogEntity()I
    .locals 2
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nGetFogEntity(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getFogOptions()Lcom/google/android/filament/View$FogOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mFogOptions:Lcom/google/android/filament/View$FogOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$FogOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$FogOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mFogOptions:Lcom/google/android/filament/View$FogOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mFogOptions:Lcom/google/android/filament/View$FogOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getGuardBandOptions()Lcom/google/android/filament/View$GuardBandOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mGuardBandOptions:Lcom/google/android/filament/View$GuardBandOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$GuardBandOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$GuardBandOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mGuardBandOptions:Lcom/google/android/filament/View$GuardBandOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mGuardBandOptions:Lcom/google/android/filament/View$GuardBandOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getMaterialGlobal(I[F)[F
    .locals 2

    .line 1
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat4([F)[F

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/View;->nGetMaterialGlobal(JI[F)V

    .line 10
    .line 11
    .line 12
    return-object p2
.end method

.method public getMultiSampleAntiAliasingOptions()Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mMultiSampleAntiAliasingOptions:Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mMultiSampleAntiAliasingOptions:Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mMultiSampleAntiAliasingOptions:Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/View;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed View"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getRenderQuality()Lcom/google/android/filament/View$RenderQuality;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mRenderQuality:Lcom/google/android/filament/View$RenderQuality;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$RenderQuality;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$RenderQuality;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mRenderQuality:Lcom/google/android/filament/View$RenderQuality;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mRenderQuality:Lcom/google/android/filament/View$RenderQuality;

    .line 13
    .line 14
    return-object p0
.end method

.method public getRenderTarget()Lcom/google/android/filament/RenderTarget;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mRenderTarget:Lcom/google/android/filament/RenderTarget;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSampleCount()I
    .locals 2
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nGetSampleCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getScene()Lcom/google/android/filament/Scene;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mScene:Lcom/google/android/filament/Scene;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScreenSpaceReflectionsOptions()Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mScreenSpaceReflectionsOptions:Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mScreenSpaceReflectionsOptions:Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mScreenSpaceReflectionsOptions:Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getSoftShadowOptions()Lcom/google/android/filament/View$SoftShadowOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mSoftShadowOptions:Lcom/google/android/filament/View$SoftShadowOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$SoftShadowOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$SoftShadowOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mSoftShadowOptions:Lcom/google/android/filament/View$SoftShadowOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mSoftShadowOptions:Lcom/google/android/filament/View$SoftShadowOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getStereoscopicOptions()Lcom/google/android/filament/View$StereoscopicOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mStereoscopicOptions:Lcom/google/android/filament/View$StereoscopicOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$StereoscopicOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$StereoscopicOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mStereoscopicOptions:Lcom/google/android/filament/View$StereoscopicOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mStereoscopicOptions:Lcom/google/android/filament/View$StereoscopicOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getTemporalAntiAliasingOptions()Lcom/google/android/filament/View$TemporalAntiAliasingOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mTemporalAntiAliasingOptions:Lcom/google/android/filament/View$TemporalAntiAliasingOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mTemporalAntiAliasingOptions:Lcom/google/android/filament/View$TemporalAntiAliasingOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mTemporalAntiAliasingOptions:Lcom/google/android/filament/View$TemporalAntiAliasingOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getToneMapping()Lcom/google/android/filament/View$ToneMapping;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    sget-object p0, Lcom/google/android/filament/View$ToneMapping;->ACES:Lcom/google/android/filament/View$ToneMapping;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewport()Lcom/google/android/filament/Viewport;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/View;->mViewport:Lcom/google/android/filament/Viewport;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVignetteOptions()Lcom/google/android/filament/View$VignetteOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mVignetteOptions:Lcom/google/android/filament/View$VignetteOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$VignetteOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$VignetteOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mVignetteOptions:Lcom/google/android/filament/View$VignetteOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mVignetteOptions:Lcom/google/android/filament/View$VignetteOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getVsmShadowOptions()Lcom/google/android/filament/View$VsmShadowOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View;->mVsmShadowOptions:Lcom/google/android/filament/View$VsmShadowOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/View$VsmShadowOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/View$VsmShadowOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/View;->mVsmShadowOptions:Lcom/google/android/filament/View$VsmShadowOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/View;->mVsmShadowOptions:Lcom/google/android/filament/View$VsmShadowOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public hasCamera()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nHasCamera(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isFrontFaceWindingInverted()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nIsFrontFaceWindingInverted(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isPostProcessingEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nIsPostProcessingEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isScreenSpaceRefractionEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nIsScreenSpaceRefractionEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isShadowingEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nIsShadowingEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isStencilBufferEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nIsStencilBufferEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isTransparentPickingEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/View;->nIsTransparentPickingEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public pick(IILjava/lang/Object;Lcom/google/android/filament/View$OnPickCallback;)V
    .locals 6

    .line 1
    new-instance v5, Lcom/google/android/filament/View$InternalOnPickCallback;

    .line 2
    .line 3
    invoke-direct {v5, p4}, Lcom/google/android/filament/View$InternalOnPickCallback;-><init>(Lcom/google/android/filament/View$OnPickCallback;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    move v2, p1

    .line 11
    move v3, p2

    .line 12
    move-object v4, p3

    .line 13
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/View;->nPick(JIILjava/lang/Object;Lcom/google/android/filament/View$InternalOnPickCallback;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setAmbientOcclusion(Lcom/google/android/filament/View$AmbientOcclusion;)V
    .locals 2
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetAmbientOcclusion(JI)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setAmbientOcclusionOptions(Lcom/google/android/filament/View$AmbientOcclusionOptions;)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iput-object v1, v0, Lcom/google/android/filament/View;->mAmbientOcclusionOptions:Lcom/google/android/filament/View$AmbientOcclusionOptions;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    iget v4, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->radius:F

    .line 12
    .line 13
    iget v5, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->bias:F

    .line 14
    .line 15
    iget v6, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->power:F

    .line 16
    .line 17
    iget v7, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->resolution:F

    .line 18
    .line 19
    iget v8, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->intensity:F

    .line 20
    .line 21
    iget v9, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->bilateralThreshold:F

    .line 22
    .line 23
    iget-object v10, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->quality:Lcom/google/android/filament/View$QualityLevel;

    .line 24
    .line 25
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result v10

    .line 29
    iget-object v11, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->lowPassFilter:Lcom/google/android/filament/View$QualityLevel;

    .line 30
    .line 31
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 32
    .line 33
    .line 34
    move-result v11

    .line 35
    iget-object v12, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->upsampling:Lcom/google/android/filament/View$QualityLevel;

    .line 36
    .line 37
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 38
    .line 39
    .line 40
    move-result v12

    .line 41
    iget-boolean v13, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->enabled:Z

    .line 42
    .line 43
    iget-boolean v14, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->bentNormals:Z

    .line 44
    .line 45
    iget v15, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->minHorizonAngleRad:F

    .line 46
    .line 47
    invoke-static/range {v2 .. v15}, Lcom/google/android/filament/View;->nSetAmbientOcclusionOptions(JFFFFFFIIIZZF)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 51
    .line 52
    .line 53
    move-result-wide v16

    .line 54
    iget v0, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctLightConeRad:F

    .line 55
    .line 56
    iget v2, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctShadowDistance:F

    .line 57
    .line 58
    iget v3, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctContactDistanceMax:F

    .line 59
    .line 60
    iget v4, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctIntensity:F

    .line 61
    .line 62
    iget-object v5, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctLightDirection:[F

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    aget v22, v5, v6

    .line 66
    .line 67
    const/4 v6, 0x1

    .line 68
    aget v23, v5, v6

    .line 69
    .line 70
    const/4 v6, 0x2

    .line 71
    aget v24, v5, v6

    .line 72
    .line 73
    iget v5, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctDepthBias:F

    .line 74
    .line 75
    iget v6, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctDepthSlopeBias:F

    .line 76
    .line 77
    iget v7, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctSampleCount:I

    .line 78
    .line 79
    iget v8, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctRayCount:I

    .line 80
    .line 81
    iget-boolean v1, v1, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctEnabled:Z

    .line 82
    .line 83
    move/from16 v18, v0

    .line 84
    .line 85
    move/from16 v29, v1

    .line 86
    .line 87
    move/from16 v19, v2

    .line 88
    .line 89
    move/from16 v20, v3

    .line 90
    .line 91
    move/from16 v21, v4

    .line 92
    .line 93
    move/from16 v25, v5

    .line 94
    .line 95
    move/from16 v26, v6

    .line 96
    .line 97
    move/from16 v27, v7

    .line 98
    .line 99
    move/from16 v28, v8

    .line 100
    .line 101
    invoke-static/range {v16 .. v29}, Lcom/google/android/filament/View;->nSetSSCTOptions(JFFFFFFFFFIIZ)V

    .line 102
    .line 103
    .line 104
    return-void
.end method

.method public setAntiAliasing(Lcom/google/android/filament/View$AntiAliasing;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetAntiAliasing(JI)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setBlendMode(Lcom/google/android/filament/View$BlendMode;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mBlendMode:Lcom/google/android/filament/View$BlendMode;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetBlendMode(JI)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public setBloomOptions(Lcom/google/android/filament/View$BloomOptions;)V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iput-object v1, v0, Lcom/google/android/filament/View;->mBloomOptions:Lcom/google/android/filament/View$BloomOptions;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    iget-object v0, v1, Lcom/google/android/filament/View$BloomOptions;->dirt:Lcom/google/android/filament/Texture;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 16
    .line 17
    .line 18
    move-result-wide v4

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-wide/16 v4, 0x0

    .line 21
    .line 22
    :goto_0
    iget v0, v1, Lcom/google/android/filament/View$BloomOptions;->dirtStrength:F

    .line 23
    .line 24
    move-wide v6, v2

    .line 25
    move-wide v2, v4

    .line 26
    iget v5, v1, Lcom/google/android/filament/View$BloomOptions;->strength:F

    .line 27
    .line 28
    move-wide v7, v6

    .line 29
    iget v6, v1, Lcom/google/android/filament/View$BloomOptions;->resolution:I

    .line 30
    .line 31
    move-wide v8, v7

    .line 32
    iget v7, v1, Lcom/google/android/filament/View$BloomOptions;->levels:I

    .line 33
    .line 34
    iget-object v4, v1, Lcom/google/android/filament/View$BloomOptions;->blendMode:Lcom/google/android/filament/View$BloomOptions$BlendMode;

    .line 35
    .line 36
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    move-wide v10, v8

    .line 41
    iget-boolean v9, v1, Lcom/google/android/filament/View$BloomOptions;->threshold:Z

    .line 42
    .line 43
    move-wide v11, v10

    .line 44
    iget-boolean v10, v1, Lcom/google/android/filament/View$BloomOptions;->enabled:Z

    .line 45
    .line 46
    move-wide v12, v11

    .line 47
    iget v11, v1, Lcom/google/android/filament/View$BloomOptions;->highlight:F

    .line 48
    .line 49
    move-wide v13, v12

    .line 50
    iget-boolean v12, v1, Lcom/google/android/filament/View$BloomOptions;->lensFlare:Z

    .line 51
    .line 52
    move-wide v14, v13

    .line 53
    iget-boolean v13, v1, Lcom/google/android/filament/View$BloomOptions;->starburst:Z

    .line 54
    .line 55
    move-wide v15, v14

    .line 56
    iget v14, v1, Lcom/google/android/filament/View$BloomOptions;->chromaticAberration:F

    .line 57
    .line 58
    move-wide/from16 v16, v15

    .line 59
    .line 60
    iget v15, v1, Lcom/google/android/filament/View$BloomOptions;->ghostCount:I

    .line 61
    .line 62
    iget v8, v1, Lcom/google/android/filament/View$BloomOptions;->ghostSpacing:F

    .line 63
    .line 64
    move/from16 v18, v0

    .line 65
    .line 66
    iget v0, v1, Lcom/google/android/filament/View$BloomOptions;->ghostThreshold:F

    .line 67
    .line 68
    move/from16 v19, v0

    .line 69
    .line 70
    iget v0, v1, Lcom/google/android/filament/View$BloomOptions;->haloThickness:F

    .line 71
    .line 72
    move/from16 v20, v0

    .line 73
    .line 74
    iget v0, v1, Lcom/google/android/filament/View$BloomOptions;->haloRadius:F

    .line 75
    .line 76
    iget v1, v1, Lcom/google/android/filament/View$BloomOptions;->haloThreshold:F

    .line 77
    .line 78
    move/from16 v21, v19

    .line 79
    .line 80
    move/from16 v19, v0

    .line 81
    .line 82
    move/from16 v22, v20

    .line 83
    .line 84
    move/from16 v20, v1

    .line 85
    .line 86
    move-wide/from16 v0, v16

    .line 87
    .line 88
    move/from16 v17, v21

    .line 89
    .line 90
    move/from16 v16, v8

    .line 91
    .line 92
    move v8, v4

    .line 93
    move/from16 v4, v18

    .line 94
    .line 95
    move/from16 v18, v22

    .line 96
    .line 97
    invoke-static/range {v0 .. v20}, Lcom/google/android/filament/View;->nSetBloomOptions(JJFFIIIZZFZZFIFFFFF)V

    .line 98
    .line 99
    .line 100
    return-void
.end method

.method public setCamera(Lcom/google/android/filament/Camera;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mCamera:Lcom/google/android/filament/Camera;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    const-wide/16 p0, 0x0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p1}, Lcom/google/android/filament/Camera;->getNativeObject()J

    .line 13
    .line 14
    .line 15
    move-result-wide p0

    .line 16
    :goto_0
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/View;->nSetCamera(JJ)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public setColorGrading(Lcom/google/android/filament/ColorGrading;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Lcom/google/android/filament/ColorGrading;->getNativeObject()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-wide/16 v2, 0x0

    .line 13
    .line 14
    :goto_0
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/View;->nSetColorGrading(JJ)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lcom/google/android/filament/View;->mColorGrading:Lcom/google/android/filament/ColorGrading;

    .line 18
    .line 19
    return-void
.end method

.method public setDepthOfFieldOptions(Lcom/google/android/filament/View$DepthOfFieldOptions;)V
    .locals 12

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mDepthOfFieldOptions:Lcom/google/android/filament/View$DepthOfFieldOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget v2, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->cocScale:F

    .line 8
    .line 9
    iget v3, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->maxApertureDiameter:F

    .line 10
    .line 11
    iget-boolean v4, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->enabled:Z

    .line 12
    .line 13
    iget-object p0, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->filter:Lcom/google/android/filament/View$DepthOfFieldOptions$Filter;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    iget-boolean v6, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->nativeResolution:Z

    .line 20
    .line 21
    iget v7, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->foregroundRingCount:I

    .line 22
    .line 23
    iget v8, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->backgroundRingCount:I

    .line 24
    .line 25
    iget v9, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->fastGatherRingCount:I

    .line 26
    .line 27
    iget v10, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->maxForegroundCOC:I

    .line 28
    .line 29
    iget v11, p1, Lcom/google/android/filament/View$DepthOfFieldOptions;->maxBackgroundCOC:I

    .line 30
    .line 31
    invoke-static/range {v0 .. v11}, Lcom/google/android/filament/View;->nSetDepthOfFieldOptions(JFFZIZIIIII)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public setDithering(Lcom/google/android/filament/View$Dithering;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetDithering(JI)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setDynamicLightingOptions(FF)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/View;->nSetDynamicLightingOptions(JFF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setDynamicResolutionOptions(Lcom/google/android/filament/View$DynamicResolutionOptions;)V
    .locals 8

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mDynamicResolution:Lcom/google/android/filament/View$DynamicResolutionOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-boolean v2, p1, Lcom/google/android/filament/View$DynamicResolutionOptions;->enabled:Z

    .line 8
    .line 9
    iget-boolean v3, p1, Lcom/google/android/filament/View$DynamicResolutionOptions;->homogeneousScaling:Z

    .line 10
    .line 11
    iget v4, p1, Lcom/google/android/filament/View$DynamicResolutionOptions;->minScale:F

    .line 12
    .line 13
    iget v5, p1, Lcom/google/android/filament/View$DynamicResolutionOptions;->maxScale:F

    .line 14
    .line 15
    iget v6, p1, Lcom/google/android/filament/View$DynamicResolutionOptions;->sharpness:F

    .line 16
    .line 17
    iget-object p0, p1, Lcom/google/android/filament/View$DynamicResolutionOptions;->quality:Lcom/google/android/filament/View$QualityLevel;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/View;->nSetDynamicResolutionOptions(JZZFFFI)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public setFogOptions(Lcom/google/android/filament/View$FogOptions;)V
    .locals 20

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/android/filament/View$FogOptions;->color:[F

    .line 4
    .line 5
    invoke-static {v1}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p0

    .line 9
    .line 10
    iput-object v0, v1, Lcom/google/android/filament/View;->mFogOptions:Lcom/google/android/filament/View$FogOptions;

    .line 11
    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    move-wide v3, v1

    .line 17
    iget v2, v0, Lcom/google/android/filament/View$FogOptions;->distance:F

    .line 18
    .line 19
    move-wide v4, v3

    .line 20
    iget v3, v0, Lcom/google/android/filament/View$FogOptions;->maximumOpacity:F

    .line 21
    .line 22
    move-wide v5, v4

    .line 23
    iget v4, v0, Lcom/google/android/filament/View$FogOptions;->height:F

    .line 24
    .line 25
    move-wide v6, v5

    .line 26
    iget v5, v0, Lcom/google/android/filament/View$FogOptions;->heightFalloff:F

    .line 27
    .line 28
    move-wide v7, v6

    .line 29
    iget v6, v0, Lcom/google/android/filament/View$FogOptions;->cutOffDistance:F

    .line 30
    .line 31
    iget-object v1, v0, Lcom/google/android/filament/View$FogOptions;->color:[F

    .line 32
    .line 33
    const/4 v9, 0x0

    .line 34
    aget v9, v1, v9

    .line 35
    .line 36
    const/4 v10, 0x1

    .line 37
    aget v10, v1, v10

    .line 38
    .line 39
    const/4 v11, 0x2

    .line 40
    aget v1, v1, v11

    .line 41
    .line 42
    move-wide v11, v7

    .line 43
    move v8, v10

    .line 44
    iget v10, v0, Lcom/google/android/filament/View$FogOptions;->density:F

    .line 45
    .line 46
    move-wide v12, v11

    .line 47
    iget v11, v0, Lcom/google/android/filament/View$FogOptions;->inScatteringStart:F

    .line 48
    .line 49
    move-wide v13, v12

    .line 50
    iget v12, v0, Lcom/google/android/filament/View$FogOptions;->inScatteringSize:F

    .line 51
    .line 52
    move-wide v14, v13

    .line 53
    iget-boolean v13, v0, Lcom/google/android/filament/View$FogOptions;->fogColorFromIbl:Z

    .line 54
    .line 55
    iget-object v7, v0, Lcom/google/android/filament/View$FogOptions;->skyColor:Lcom/google/android/filament/Texture;

    .line 56
    .line 57
    if-nez v7, :cond_0

    .line 58
    .line 59
    const-wide/16 v16, 0x0

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-virtual {v7}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 63
    .line 64
    .line 65
    move-result-wide v16

    .line 66
    :goto_0
    iget-boolean v0, v0, Lcom/google/android/filament/View$FogOptions;->enabled:Z

    .line 67
    .line 68
    move v7, v9

    .line 69
    move v9, v1

    .line 70
    move-wide/from16 v18, v16

    .line 71
    .line 72
    move/from16 v16, v0

    .line 73
    .line 74
    move-wide v0, v14

    .line 75
    move-wide/from16 v14, v18

    .line 76
    .line 77
    invoke-static/range {v0 .. v16}, Lcom/google/android/filament/View;->nSetFogOptions(JFFFFFFFFFFFZJZ)V

    .line 78
    .line 79
    .line 80
    return-void
.end method

.method public setFrontFaceWindingInverted(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetFrontFaceWindingInverted(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setGuardBandOptions(Lcom/google/android/filament/View$GuardBandOptions;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mGuardBandOptions:Lcom/google/android/filament/View$GuardBandOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-boolean p0, p1, Lcom/google/android/filament/View$GuardBandOptions;->enabled:Z

    .line 8
    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetGuardBandOptions(JZ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setMaterialGlobal(I[F)V
    .locals 7

    .line 1
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat4In([F)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    const/4 p0, 0x0

    .line 9
    aget v3, p2, p0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    aget v4, p2, p0

    .line 13
    .line 14
    const/4 p0, 0x2

    .line 15
    aget v5, p2, p0

    .line 16
    .line 17
    const/4 p0, 0x3

    .line 18
    aget v6, p2, p0

    .line 19
    .line 20
    move v2, p1

    .line 21
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/View;->nSetMaterialGlobal(JIFFFF)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public setMultiSampleAntiAliasingOptions(Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mMultiSampleAntiAliasingOptions:Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-boolean p0, p1, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;->enabled:Z

    .line 8
    .line 9
    iget v2, p1, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;->sampleCount:I

    .line 10
    .line 11
    iget-boolean p1, p1, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;->customResolve:Z

    .line 12
    .line 13
    invoke-static {v0, v1, p0, v2, p1}, Lcom/google/android/filament/View;->nSetMultiSampleAntiAliasingOptions(JZIZ)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setName(Ljava/lang/String;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mName:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetName(JLjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setPostProcessingEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetPostProcessingEnabled(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setRenderQuality(Lcom/google/android/filament/View$RenderQuality;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mRenderQuality:Lcom/google/android/filament/View$RenderQuality;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p0, p1, Lcom/google/android/filament/View$RenderQuality;->hdrColorBuffer:Lcom/google/android/filament/View$QualityLevel;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetRenderQuality(JI)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setRenderTarget(Lcom/google/android/filament/RenderTarget;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mRenderTarget:Lcom/google/android/filament/RenderTarget;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const-wide/16 p0, 0x0

    .line 15
    .line 16
    :goto_0
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/View;->nSetRenderTarget(JJ)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public setSampleCount(I)V
    .locals 2
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetSampleCount(JI)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setScene(Lcom/google/android/filament/Scene;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mScene:Lcom/google/android/filament/Scene;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    const-wide/16 p0, 0x0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p1}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 13
    .line 14
    .line 15
    move-result-wide p0

    .line 16
    :goto_0
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/View;->nSetScene(JJ)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public setScreenSpaceReflectionsOptions(Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;)V
    .locals 7

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mScreenSpaceReflectionsOptions:Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget v2, p1, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->thickness:F

    .line 8
    .line 9
    iget v3, p1, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->bias:F

    .line 10
    .line 11
    iget v4, p1, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->maxDistance:F

    .line 12
    .line 13
    iget v5, p1, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->stride:F

    .line 14
    .line 15
    iget-boolean v6, p1, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->enabled:Z

    .line 16
    .line 17
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/View;->nSetScreenSpaceReflectionsOptions(JFFFFZ)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public setScreenSpaceRefractionEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetScreenSpaceRefractionEnabled(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setShadowType(Lcom/google/android/filament/View$ShadowType;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetShadowType(JI)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setShadowingEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetShadowingEnabled(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setSoftShadowOptions(Lcom/google/android/filament/View$SoftShadowOptions;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mSoftShadowOptions:Lcom/google/android/filament/View$SoftShadowOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget p0, p1, Lcom/google/android/filament/View$SoftShadowOptions;->penumbraScale:F

    .line 8
    .line 9
    iget p1, p1, Lcom/google/android/filament/View$SoftShadowOptions;->penumbraRatioScale:F

    .line 10
    .line 11
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/View;->nSetSoftShadowOptions(JFF)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public setStencilBufferEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetStencilBufferEnabled(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setStereoscopicOptions(Lcom/google/android/filament/View$StereoscopicOptions;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mStereoscopicOptions:Lcom/google/android/filament/View$StereoscopicOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-boolean p0, p1, Lcom/google/android/filament/View$StereoscopicOptions;->enabled:Z

    .line 8
    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/View;->nSetStereoscopicOptions(JZ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setTemporalAntiAliasingOptions(Lcom/google/android/filament/View$TemporalAntiAliasingOptions;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mTemporalAntiAliasingOptions:Lcom/google/android/filament/View$TemporalAntiAliasingOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget p0, p1, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->feedback:F

    .line 8
    .line 9
    iget v2, p1, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->filterWidth:F

    .line 10
    .line 11
    iget-boolean p1, p1, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->enabled:Z

    .line 12
    .line 13
    invoke-static {v0, v1, p0, v2, p1}, Lcom/google/android/filament/View;->nSetTemporalAntiAliasingOptions(JFFZ)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setToneMapping(Lcom/google/android/filament/View$ToneMapping;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public setTransparentPickingEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/View;->nSetTransparentPickingEnabled(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setViewport(Lcom/google/android/filament/Viewport;)V
    .locals 6

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mViewport:Lcom/google/android/filament/Viewport;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p0, p0, Lcom/google/android/filament/View;->mViewport:Lcom/google/android/filament/Viewport;

    .line 8
    .line 9
    iget v2, p0, Lcom/google/android/filament/Viewport;->left:I

    .line 10
    .line 11
    iget v3, p0, Lcom/google/android/filament/Viewport;->bottom:I

    .line 12
    .line 13
    iget v4, p0, Lcom/google/android/filament/Viewport;->width:I

    .line 14
    .line 15
    iget v5, p0, Lcom/google/android/filament/Viewport;->height:I

    .line 16
    .line 17
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/View;->nSetViewport(JIIII)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public setVignetteOptions(Lcom/google/android/filament/View$VignetteOptions;)V
    .locals 11

    .line 1
    iget-object v0, p1, Lcom/google/android/filament/View$VignetteOptions;->color:[F

    .line 2
    .line 3
    invoke-static {v0}, Lcom/google/android/filament/Asserts;->assertFloat4In([F)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/View;->mVignetteOptions:Lcom/google/android/filament/View$VignetteOptions;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 9
    .line 10
    .line 11
    move-result-wide v1

    .line 12
    iget v3, p1, Lcom/google/android/filament/View$VignetteOptions;->midPoint:F

    .line 13
    .line 14
    iget v4, p1, Lcom/google/android/filament/View$VignetteOptions;->roundness:F

    .line 15
    .line 16
    iget v5, p1, Lcom/google/android/filament/View$VignetteOptions;->feather:F

    .line 17
    .line 18
    iget-object p0, p1, Lcom/google/android/filament/View$VignetteOptions;->color:[F

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    aget v6, p0, v0

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    aget v7, p0, v0

    .line 25
    .line 26
    const/4 v0, 0x2

    .line 27
    aget v8, p0, v0

    .line 28
    .line 29
    const/4 v0, 0x3

    .line 30
    aget v9, p0, v0

    .line 31
    .line 32
    iget-boolean v10, p1, Lcom/google/android/filament/View$VignetteOptions;->enabled:Z

    .line 33
    .line 34
    invoke-static/range {v1 .. v10}, Lcom/google/android/filament/View;->nSetVignetteOptions(JFFFFFFFZ)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public setVisibleLayers(II)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    and-int/lit16 p0, p1, 0xff

    .line 6
    .line 7
    and-int/lit16 p1, p2, 0xff

    .line 8
    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/View;->nSetVisibleLayers(JII)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setVsmShadowOptions(Lcom/google/android/filament/View$VsmShadowOptions;)V
    .locals 7

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/View;->mVsmShadowOptions:Lcom/google/android/filament/View$VsmShadowOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget v2, p1, Lcom/google/android/filament/View$VsmShadowOptions;->anisotropy:I

    .line 8
    .line 9
    iget-boolean v3, p1, Lcom/google/android/filament/View$VsmShadowOptions;->mipmapping:Z

    .line 10
    .line 11
    iget-boolean v4, p1, Lcom/google/android/filament/View$VsmShadowOptions;->highPrecision:Z

    .line 12
    .line 13
    iget v5, p1, Lcom/google/android/filament/View$VsmShadowOptions;->minVarianceScale:F

    .line 14
    .line 15
    iget v6, p1, Lcom/google/android/filament/View$VsmShadowOptions;->lightBleedReduction:F

    .line 16
    .line 17
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/View;->nSetVsmShadowOptions(JIZZFF)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
