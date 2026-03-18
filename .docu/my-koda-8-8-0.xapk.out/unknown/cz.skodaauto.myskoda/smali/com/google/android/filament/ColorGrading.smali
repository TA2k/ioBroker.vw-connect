.class public Lcom/google/android/filament/ColorGrading;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/ColorGrading$Builder;,
        Lcom/google/android/filament/ColorGrading$ToneMapping;,
        Lcom/google/android/filament/ColorGrading$LutFormat;,
        Lcom/google/android/filament/ColorGrading$QualityLevel;
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
    iput-wide p1, p0, Lcom/google/android/filament/ColorGrading;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method public static bridge synthetic a(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/ColorGrading;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(J[F[F[F)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/ColorGrading;->nBuilderChannelMixer(J[F[F[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderContrast(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(J[F[F[F)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/ColorGrading;->nBuilderCurves(J[F[F[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/ColorGrading;->nBuilderDimensions(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderExposure(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/ColorGrading;->nBuilderFormat(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic h(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderGamutMapping(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderLuminanceScaling(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic j(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderNightAdaptation(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/ColorGrading;->nBuilderQuality(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic l(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderSaturation(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic m(J[F[F[F[F)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Lcom/google/android/filament/ColorGrading;->nBuilderShadowsMidtonesHighlights(J[F[F[F[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic n(J[F[F[F)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/ColorGrading;->nBuilderSlopeOffsetPower(J[F[F[F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderChannelMixer(J[F[F[F)V
.end method

.method private static native nBuilderContrast(JF)V
.end method

.method private static native nBuilderCurves(J[F[F[F)V
.end method

.method private static native nBuilderDimensions(JI)V
.end method

.method private static native nBuilderExposure(JF)V
.end method

.method private static native nBuilderFormat(JI)V
.end method

.method private static native nBuilderGamutMapping(JZ)V
.end method

.method private static native nBuilderLuminanceScaling(JZ)V
.end method

.method private static native nBuilderNightAdaptation(JF)V
.end method

.method private static native nBuilderQuality(JI)V
.end method

.method private static native nBuilderSaturation(JF)V
.end method

.method private static native nBuilderShadowsMidtonesHighlights(J[F[F[F[F)V
.end method

.method private static native nBuilderSlopeOffsetPower(J[F[F[F)V
.end method

.method private static native nBuilderToneMapper(JJ)V
.end method

.method private static native nBuilderToneMapping(JI)V
.end method

.method private static native nBuilderVibrance(JF)V
.end method

.method private static native nBuilderWhiteBalance(JFF)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method public static bridge synthetic o(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/ColorGrading;->nBuilderToneMapper(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic p(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/ColorGrading;->nBuilderToneMapping(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic q(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ColorGrading;->nBuilderVibrance(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic r(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/ColorGrading;->nBuilderWhiteBalance(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic s()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/ColorGrading;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic t(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/ColorGrading;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/ColorGrading;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed ColorGrading"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method
