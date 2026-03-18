.class public Lcom/google/android/filament/ColorGrading$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/ColorGrading;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/ColorGrading$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/ColorGrading$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/ColorGrading;->s()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/ColorGrading$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/ColorGrading$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/ColorGrading$Builder;->mFinalizer:Lcom/google/android/filament/ColorGrading$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/ColorGrading;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/ColorGrading;->a(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    cmp-long v0, p0, v0

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Lcom/google/android/filament/ColorGrading;

    .line 18
    .line 19
    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/ColorGrading;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "Couldn\'t create ColorGrading"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public channelMixer([F[F[F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 5
    .line 6
    .line 7
    invoke-static {p3}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 8
    .line 9
    .line 10
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 11
    .line 12
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/ColorGrading;->b(J[F[F[F)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public contrast(F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->c(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public curves([F[F[F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 5
    .line 6
    .line 7
    invoke-static {p3}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 8
    .line 9
    .line 10
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 11
    .line 12
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/ColorGrading;->d(J[F[F[F)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public dimensions(I)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/ColorGrading;->e(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public exposure(F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->f(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public format(Lcom/google/android/filament/ColorGrading$LutFormat;)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/ColorGrading;->g(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public gamutMapping(Z)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->h(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public luminanceScaling(Z)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->i(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public nightAdaptation(F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->j(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public quality(Lcom/google/android/filament/ColorGrading$QualityLevel;)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/ColorGrading;->k(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public saturation(F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->l(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public shadowsMidtonesHighlights([F[F[F[F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 6

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat4In([F)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat4In([F)V

    .line 5
    .line 6
    .line 7
    invoke-static {p3}, Lcom/google/android/filament/Asserts;->assertFloat4In([F)V

    .line 8
    .line 9
    .line 10
    invoke-static {p4}, Lcom/google/android/filament/Asserts;->assertFloat4In([F)V

    .line 11
    .line 12
    .line 13
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 14
    .line 15
    move-object v2, p1

    .line 16
    move-object v3, p2

    .line 17
    move-object v4, p3

    .line 18
    move-object v5, p4

    .line 19
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/ColorGrading;->m(J[F[F[F[F)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public slopeOffsetPower([F[F[F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 5
    .line 6
    .line 7
    invoke-static {p3}, Lcom/google/android/filament/Asserts;->assertFloat3In([F)V

    .line 8
    .line 9
    .line 10
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 11
    .line 12
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/ColorGrading;->n(J[F[F[F)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public toneMapper(Lcom/google/android/filament/ToneMapper;)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/ColorGrading;->o(JJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public toneMapping(Lcom/google/android/filament/ColorGrading$ToneMapping;)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/ColorGrading;->p(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public vibrance(F)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ColorGrading;->q(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public whiteBalance(FF)Lcom/google/android/filament/ColorGrading$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ColorGrading$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/ColorGrading;->r(JFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
