.class public Lcom/google/android/filament/IndirectLight;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/IndirectLight$Builder;
    }
.end annotation


# instance fields
.field mNativeObject:J


# direct methods
.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/IndirectLight;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method public static bridge synthetic a(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/IndirectLight;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/IndirectLight;->nBuilderReflections(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/IndirectLight;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic d(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/IndirectLight;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/IndirectLight;->nIntensity(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(JI[F)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/IndirectLight;->nIrradiance(JI[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/IndirectLight;->nIrradianceAsTexture(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getColorEstimate([F[FFFF)[F
    .locals 2

    .line 1
    array-length v0, p1

    const/16 v1, 0x1b

    if-lt v0, v1, :cond_0

    .line 2
    invoke-static {p0}, Lcom/google/android/filament/Asserts;->assertFloat4([F)[F

    move-result-object p0

    .line 3
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/IndirectLight;->nGetColorEstimateStatic([F[FFFF)V

    return-object p0

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    const-string p1, "3 bands SH required, array must be at least 9 x float3"

    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static getDirectionEstimate([F[F)[F
    .locals 2

    .line 1
    array-length v0, p0

    const/16 v1, 0x1b

    if-lt v0, v1, :cond_0

    .line 2
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat3([F)[F

    move-result-object p1

    .line 3
    invoke-static {p0, p1}, Lcom/google/android/filament/IndirectLight;->nGetDirectionEstimateStatic([F[F)V

    return-object p1

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    const-string p1, "3 bands SH required, array must be at least 9 x float3"

    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static bridge synthetic h(JI[F)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/IndirectLight;->nRadiance(JI[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(JFFFFFFFFF)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p10}, Lcom/google/android/filament/IndirectLight;->nRotation(JFFFFFFFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderReflections(JJ)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetColorEstimate(J[FFFF)V
.end method

.method private static native nGetColorEstimateStatic([F[FFFF)V
.end method

.method private static native nGetDirectionEstimate(J[F)V
.end method

.method private static native nGetDirectionEstimateStatic([F[F)V
.end method

.method private static native nGetIntensity(J)F
.end method

.method private static native nGetIrradianceTexture(J)J
.end method

.method private static native nGetReflectionsTexture(J)J
.end method

.method private static native nGetRotation(J[F)V
.end method

.method private static native nIntensity(JF)V
.end method

.method private static native nIrradiance(JI[F)V
.end method

.method private static native nIrradianceAsTexture(JJ)V
.end method

.method private static native nRadiance(JI[F)V
.end method

.method private static native nRotation(JFFFFFFFFF)V
.end method

.method private static native nSetIntensity(JF)V
.end method

.method private static native nSetRotation(JFFFFFFFFF)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/IndirectLight;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getColorEstimate([FFFF)[F
    .locals 6
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 5
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat4([F)[F

    move-result-object v2

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    move-result-wide v0

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/IndirectLight;->nGetColorEstimate(J[FFFF)V

    return-object v2
.end method

.method public getDirectionEstimate([F)[F
    .locals 2
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 5
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat3([F)[F

    move-result-object p1

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    move-result-wide v0

    invoke-static {v0, v1, p1}, Lcom/google/android/filament/IndirectLight;->nGetDirectionEstimate(J[F)V

    return-object p1
.end method

.method public getIntensity()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/IndirectLight;->nGetIntensity(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getIrradianceTexture()Lcom/google/android/filament/Texture;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/IndirectLight;->nGetIrradianceTexture(J)J

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
    new-instance p0, Lcom/google/android/filament/Texture;

    .line 18
    .line 19
    invoke-direct {p0, v0, v1}, Lcom/google/android/filament/Texture;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed IndirectLight"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getReflectionsTexture()Lcom/google/android/filament/Texture;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/IndirectLight;->nGetReflectionsTexture(J)J

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
    new-instance p0, Lcom/google/android/filament/Texture;

    .line 18
    .line 19
    invoke-direct {p0, v0, v1}, Lcom/google/android/filament/Texture;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public getRotation([F)[F
    .locals 2

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertMat3f([F)[F

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/IndirectLight;->nGetRotation(J[F)V

    .line 10
    .line 11
    .line 12
    return-object p1
.end method

.method public setIntensity(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/IndirectLight;->nSetIntensity(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setRotation([F)V
    .locals 11

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertMat3fIn([F)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    const/4 p0, 0x0

    .line 9
    aget v2, p1, p0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    aget v3, p1, p0

    .line 13
    .line 14
    const/4 p0, 0x2

    .line 15
    aget v4, p1, p0

    .line 16
    .line 17
    const/4 p0, 0x3

    .line 18
    aget v5, p1, p0

    .line 19
    .line 20
    const/4 p0, 0x4

    .line 21
    aget v6, p1, p0

    .line 22
    .line 23
    const/4 p0, 0x5

    .line 24
    aget v7, p1, p0

    .line 25
    .line 26
    const/4 p0, 0x6

    .line 27
    aget v8, p1, p0

    .line 28
    .line 29
    const/4 p0, 0x7

    .line 30
    aget v9, p1, p0

    .line 31
    .line 32
    const/16 p0, 0x8

    .line 33
    .line 34
    aget v10, p1, p0

    .line 35
    .line 36
    invoke-static/range {v0 .. v10}, Lcom/google/android/filament/IndirectLight;->nSetRotation(JFFFFFFFFF)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
