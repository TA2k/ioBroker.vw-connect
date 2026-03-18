.class public Lcom/google/android/filament/MaterialInstance;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "AssetLoader.cpp"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/MaterialInstance$BooleanElement;,
        Lcom/google/android/filament/MaterialInstance$IntElement;,
        Lcom/google/android/filament/MaterialInstance$FloatElement;,
        Lcom/google/android/filament/MaterialInstance$StencilFace;,
        Lcom/google/android/filament/MaterialInstance$StencilOperation;
    }
.end annotation


# static fields
.field private static final sCullingModeValues:[Lcom/google/android/filament/Material$CullingMode;

.field static final sStencilFaceMapping:[I


# instance fields
.field private mMaterial:Lcom/google/android/filament/Material;

.field private mName:Ljava/lang/String;

.field private mNativeMaterial:J

.field private mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Lcom/google/android/filament/Material$CullingMode;->values()[Lcom/google/android/filament/Material$CullingMode;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/MaterialInstance;->sCullingModeValues:[Lcom/google/android/filament/Material$CullingMode;

    .line 6
    .line 7
    const/4 v0, 0x2

    .line 8
    const/4 v1, 0x3

    .line 9
    const/4 v2, 0x1

    .line 10
    filled-new-array {v2, v0, v1}, [I

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(J)V
    .locals 0

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-wide p1, p0, Lcom/google/android/filament/MaterialInstance;->mNativeObject:J

    .line 10
    invoke-static {p1, p2}, Lcom/google/android/filament/MaterialInstance;->nGetMaterial(J)J

    move-result-wide p1

    iput-wide p1, p0, Lcom/google/android/filament/MaterialInstance;->mNativeMaterial:J

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/Engine;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-wide p2, p0, Lcom/google/android/filament/MaterialInstance;->mNativeObject:J

    .line 3
    invoke-static {p2, p3}, Lcom/google/android/filament/MaterialInstance;->nGetMaterial(J)J

    move-result-wide p1

    iput-wide p1, p0, Lcom/google/android/filament/MaterialInstance;->mNativeMaterial:J

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/Material;J)V
    .locals 2

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lcom/google/android/filament/MaterialInstance;->mMaterial:Lcom/google/android/filament/Material;

    .line 6
    invoke-virtual {p1}, Lcom/google/android/filament/Material;->getNativeObject()J

    move-result-wide v0

    iput-wide v0, p0, Lcom/google/android/filament/MaterialInstance;->mNativeMaterial:J

    .line 7
    iput-wide p2, p0, Lcom/google/android/filament/MaterialInstance;->mNativeObject:J

    return-void
.end method

.method public static duplicate(Lcom/google/android/filament/MaterialInstance;Ljava/lang/String;)Lcom/google/android/filament/MaterialInstance;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MaterialInstance;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nDuplicate(JLjava/lang/String;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    cmp-long p1, v0, v2

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    new-instance p1, Lcom/google/android/filament/MaterialInstance;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getMaterial()Lcom/google/android/filament/Material;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {p1, p0, v0, v1}, Lcom/google/android/filament/MaterialInstance;-><init>(Lcom/google/android/filament/Material;J)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "Couldn\'t duplicate MaterialInstance"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method private static native nDuplicate(JLjava/lang/String;)J
.end method

.method private static native nGetCullingMode(J)I
.end method

.method private static native nGetDepthFunc(J)I
.end method

.method private static native nGetMaskThreshold(J)F
.end method

.method private static native nGetMaterial(J)J
.end method

.method private static native nGetName(J)Ljava/lang/String;
.end method

.method private static native nGetSpecularAntiAliasingThreshold(J)F
.end method

.method private static native nGetSpecularAntiAliasingVariance(J)F
.end method

.method private static native nIsColorWriteEnabled(J)Z
.end method

.method private static native nIsDepthCullingEnabled(J)Z
.end method

.method private static native nIsDepthWriteEnabled(J)Z
.end method

.method private static native nIsDoubleSided(J)Z
.end method

.method private static native nIsStencilWriteEnabled(J)Z
.end method

.method private static native nSetBooleanParameterArray(JLjava/lang/String;I[ZII)V
.end method

.method private static native nSetColorWrite(JZ)V
.end method

.method private static native nSetCullingMode(JJ)V
.end method

.method private static native nSetDepthCulling(JZ)V
.end method

.method private static native nSetDepthFunc(JJ)V
.end method

.method private static native nSetDepthWrite(JZ)V
.end method

.method private static native nSetDoubleSided(JZ)V
.end method

.method private static native nSetFloatParameterArray(JLjava/lang/String;I[FII)V
.end method

.method private static native nSetIntParameterArray(JLjava/lang/String;I[III)V
.end method

.method private static native nSetMaskThreshold(JF)V
.end method

.method private static native nSetParameterBool(JLjava/lang/String;Z)V
.end method

.method private static native nSetParameterBool2(JLjava/lang/String;ZZ)V
.end method

.method private static native nSetParameterBool3(JLjava/lang/String;ZZZ)V
.end method

.method private static native nSetParameterBool4(JLjava/lang/String;ZZZZ)V
.end method

.method private static native nSetParameterFloat(JLjava/lang/String;F)V
.end method

.method private static native nSetParameterFloat2(JLjava/lang/String;FF)V
.end method

.method private static native nSetParameterFloat3(JLjava/lang/String;FFF)V
.end method

.method private static native nSetParameterFloat4(JLjava/lang/String;FFFF)V
.end method

.method private static native nSetParameterInt(JLjava/lang/String;I)V
.end method

.method private static native nSetParameterInt2(JLjava/lang/String;II)V
.end method

.method private static native nSetParameterInt3(JLjava/lang/String;III)V
.end method

.method private static native nSetParameterInt4(JLjava/lang/String;IIII)V
.end method

.method private static native nSetParameterTexture(JLjava/lang/String;JJ)V
.end method

.method private static native nSetPolygonOffset(JFF)V
.end method

.method private static native nSetScissor(JIIII)V
.end method

.method private static native nSetSpecularAntiAliasingThreshold(JF)V
.end method

.method private static native nSetSpecularAntiAliasingVariance(JF)V
.end method

.method private static native nSetStencilCompareFunction(JJJ)V
.end method

.method private static native nSetStencilOpDepthFail(JJJ)V
.end method

.method private static native nSetStencilOpDepthStencilPass(JJJ)V
.end method

.method private static native nSetStencilOpStencilFail(JJJ)V
.end method

.method private static native nSetStencilReadMask(JIJ)V
.end method

.method private static native nSetStencilReferenceValue(JIJ)V
.end method

.method private static native nSetStencilWrite(JZ)V
.end method

.method private static native nSetStencilWriteMask(JIJ)V
.end method

.method private static native nUnsetScissor(J)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/MaterialInstance;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getCullingMode()Lcom/google/android/filament/Material$CullingMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/MaterialInstance;->sCullingModeValues:[Lcom/google/android/filament/Material$CullingMode;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/MaterialInstance;->nGetCullingMode(J)I

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

.method public getDepthFunc()Lcom/google/android/filament/TextureSampler$CompareFunction;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sCompareFunctionValues:[Lcom/google/android/filament/TextureSampler$CompareFunction;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/MaterialInstance;->nGetDepthFunc(J)I

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
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nGetMaskThreshold(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getMaterial()Lcom/google/android/filament/Material;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/MaterialInstance;->mMaterial:Lcom/google/android/filament/Material;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/Material;

    .line 6
    .line 7
    iget-wide v1, p0, Lcom/google/android/filament/MaterialInstance;->mNativeMaterial:J

    .line 8
    .line 9
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material;-><init>(J)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lcom/google/android/filament/MaterialInstance;->mMaterial:Lcom/google/android/filament/Material;

    .line 13
    .line 14
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/MaterialInstance;->mMaterial:Lcom/google/android/filament/Material;

    .line 15
    .line 16
    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/MaterialInstance;->mName:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nGetName(J)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Lcom/google/android/filament/MaterialInstance;->mName:Ljava/lang/String;

    .line 14
    .line 15
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/MaterialInstance;->mName:Ljava/lang/String;

    .line 16
    .line 17
    return-object p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MaterialInstance;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed MaterialInstance"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getSpecularAntiAliasingThreshold()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nGetSpecularAntiAliasingThreshold(J)F

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
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nGetSpecularAntiAliasingVariance(J)F

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
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nIsColorWriteEnabled(J)Z

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
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nIsDepthCullingEnabled(J)Z

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
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nIsDepthWriteEnabled(J)Z

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
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nIsDoubleSided(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isStencilWriteEnabled()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nIsStencilWriteEnabled(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public setColorWrite(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetColorWrite(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setCullingMode(Lcom/google/android/filament/Material$CullingMode;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

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
    int-to-long p0, p0

    .line 10
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/MaterialInstance;->nSetCullingMode(JJ)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public setDepthCulling(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetDepthCulling(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setDepthFunc(Lcom/google/android/filament/TextureSampler$CompareFunction;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

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
    int-to-long p0, p0

    .line 10
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/MaterialInstance;->nSetDepthFunc(JJ)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public setDepthWrite(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetDepthWrite(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setDoubleSided(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetDoubleSided(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setMaskThreshold(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetMaskThreshold(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setParameter(Ljava/lang/String;F)V
    .locals 2

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/MaterialInstance;->nSetParameterFloat(JLjava/lang/String;F)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;FF)V
    .locals 2

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->nSetParameterFloat2(JLjava/lang/String;FF)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;FFF)V
    .locals 6

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetParameterFloat3(JLjava/lang/String;FFF)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;FFFF)V
    .locals 7

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    move v6, p5

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetParameterFloat4(JLjava/lang/String;FFFF)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;I)V
    .locals 2

    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/MaterialInstance;->nSetParameterInt(JLjava/lang/String;I)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;II)V
    .locals 2

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->nSetParameterInt2(JLjava/lang/String;II)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;III)V
    .locals 6

    .line 9
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetParameterInt3(JLjava/lang/String;III)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;IIII)V
    .locals 7

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    move v6, p5

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetParameterInt4(JLjava/lang/String;IIII)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Lcom/google/android/filament/Colors$RgbType;FFF)V
    .locals 6

    .line 17
    invoke-static {p2, p3, p4, p5}, Lcom/google/android/filament/Colors;->toLinear(Lcom/google/android/filament/Colors$RgbType;FFF)[F

    move-result-object p2

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    const/4 p0, 0x0

    aget v3, p2, p0

    const/4 p0, 0x1

    aget v4, p2, p0

    const/4 p0, 0x2

    aget v5, p2, p0

    move-object v2, p1

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetParameterFloat3(JLjava/lang/String;FFF)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Lcom/google/android/filament/Colors$RgbaType;FFFF)V
    .locals 7

    .line 19
    invoke-static {p2, p3, p4, p5, p6}, Lcom/google/android/filament/Colors;->toLinear(Lcom/google/android/filament/Colors$RgbaType;FFFF)[F

    move-result-object p2

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    const/4 p0, 0x0

    aget v3, p2, p0

    const/4 p0, 0x1

    aget v4, p2, p0

    const/4 p0, 0x2

    aget v5, p2, p0

    const/4 p0, 0x3

    aget v6, p2, p0

    move-object v2, p1

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetParameterFloat4(JLjava/lang/String;FFFF)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$BooleanElement;[ZII)V
    .locals 7

    .line 14
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    move-object v2, p1

    move-object v4, p3

    move v5, p4

    move v6, p5

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetBooleanParameterArray(JLjava/lang/String;I[ZII)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$FloatElement;[FII)V
    .locals 7

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    move-object v2, p1

    move-object v4, p3

    move v5, p4

    move v6, p5

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetFloatParameterArray(JLjava/lang/String;I[FII)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Lcom/google/android/filament/MaterialInstance$IntElement;[III)V
    .locals 7

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    move-object v2, p1

    move-object v4, p3

    move v5, p4

    move v6, p5

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetIntParameterArray(JLjava/lang/String;I[III)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Lcom/google/android/filament/Texture;Lcom/google/android/filament/TextureSampler;)V
    .locals 7

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p2}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v3

    iget-wide v5, p3, Lcom/google/android/filament/TextureSampler;->mSampler:J

    move-object v2, p1

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetParameterTexture(JLjava/lang/String;JJ)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/MaterialInstance;->nSetParameterBool(JLjava/lang/String;Z)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;ZZ)V
    .locals 2

    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/MaterialInstance;->nSetParameterBool2(JLjava/lang/String;ZZ)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;ZZZ)V
    .locals 6

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetParameterBool3(JLjava/lang/String;ZZZ)V

    return-void
.end method

.method public setParameter(Ljava/lang/String;ZZZZ)V
    .locals 7

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    move v6, p5

    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MaterialInstance;->nSetParameterBool4(JLjava/lang/String;ZZZZ)V

    return-void
.end method

.method public setPolygonOffset(FF)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/MaterialInstance;->nSetPolygonOffset(JFF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setScissor(IIII)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    move v2, p1

    .line 6
    move v3, p2

    .line 7
    move v4, p3

    .line 8
    move v5, p4

    .line 9
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetScissor(JIIII)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setSpecularAntiAliasingThreshold(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetSpecularAntiAliasingThreshold(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setSpecularAntiAliasingVariance(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetSpecularAntiAliasingVariance(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setStencilCompareFunction(Lcom/google/android/filament/TextureSampler$CompareFunction;)V
    .locals 1

    .line 4
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilCompareFunction(Lcom/google/android/filament/TextureSampler$CompareFunction;Lcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilCompareFunction(Lcom/google/android/filament/TextureSampler$CompareFunction;Lcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    int-to-long v2, p0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    .line 2
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p0, p0, p1

    int-to-long v4, p0

    .line 3
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetStencilCompareFunction(JJJ)V

    return-void
.end method

.method public setStencilOpDepthFail(Lcom/google/android/filament/MaterialInstance$StencilOperation;)V
    .locals 1

    .line 4
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilOpDepthFail(Lcom/google/android/filament/MaterialInstance$StencilOperation;Lcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilOpDepthFail(Lcom/google/android/filament/MaterialInstance$StencilOperation;Lcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    int-to-long v2, p0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    .line 2
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p0, p0, p1

    int-to-long v4, p0

    .line 3
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetStencilOpDepthFail(JJJ)V

    return-void
.end method

.method public setStencilOpDepthStencilPass(Lcom/google/android/filament/MaterialInstance$StencilOperation;)V
    .locals 1

    .line 4
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilOpDepthStencilPass(Lcom/google/android/filament/MaterialInstance$StencilOperation;Lcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilOpDepthStencilPass(Lcom/google/android/filament/MaterialInstance$StencilOperation;Lcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    int-to-long v2, p0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    .line 2
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p0, p0, p1

    int-to-long v4, p0

    .line 3
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetStencilOpDepthStencilPass(JJJ)V

    return-void
.end method

.method public setStencilOpStencilFail(Lcom/google/android/filament/MaterialInstance$StencilOperation;)V
    .locals 1

    .line 4
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilOpStencilFail(Lcom/google/android/filament/MaterialInstance$StencilOperation;Lcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilOpStencilFail(Lcom/google/android/filament/MaterialInstance$StencilOperation;Lcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    int-to-long v2, p0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    .line 2
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p0, p0, p1

    int-to-long v4, p0

    .line 3
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/MaterialInstance;->nSetStencilOpStencilFail(JJJ)V

    return-void
.end method

.method public setStencilReadMask(I)V
    .locals 1

    .line 2
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilReadMask(ILcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilReadMask(ILcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    int-to-long v2, p0

    invoke-static {v0, v1, p1, v2, v3}, Lcom/google/android/filament/MaterialInstance;->nSetStencilReadMask(JIJ)V

    return-void
.end method

.method public setStencilReferenceValue(I)V
    .locals 1

    .line 2
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilReferenceValue(ILcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilReferenceValue(ILcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    int-to-long v2, p0

    invoke-static {v0, v1, p1, v2, v3}, Lcom/google/android/filament/MaterialInstance;->nSetStencilReferenceValue(JIJ)V

    return-void
.end method

.method public setStencilWrite(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/MaterialInstance;->nSetStencilWrite(JZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setStencilWriteMask(I)V
    .locals 1

    .line 2
    sget-object v0, Lcom/google/android/filament/MaterialInstance$StencilFace;->FRONT_AND_BACK:Lcom/google/android/filament/MaterialInstance$StencilFace;

    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/MaterialInstance;->setStencilWriteMask(ILcom/google/android/filament/MaterialInstance$StencilFace;)V

    return-void
.end method

.method public setStencilWriteMask(ILcom/google/android/filament/MaterialInstance$StencilFace;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    move-result-wide v0

    sget-object p0, Lcom/google/android/filament/MaterialInstance;->sStencilFaceMapping:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    int-to-long v2, p0

    invoke-static {v0, v1, p1, v2, v3}, Lcom/google/android/filament/MaterialInstance;->nSetStencilWriteMask(JIJ)V

    return-void
.end method

.method public unsetScissor()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/MaterialInstance;->nUnsetScissor(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
