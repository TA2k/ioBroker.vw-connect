.class public Lcom/google/android/filament/IndirectLight$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/IndirectLight;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/IndirectLight$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/IndirectLight$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/IndirectLight;->c()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/IndirectLight$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/IndirectLight$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/IndirectLight$Builder;->mFinalizer:Lcom/google/android/filament/IndirectLight$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/IndirectLight;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/IndirectLight;->a(JJ)J

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
    new-instance v0, Lcom/google/android/filament/IndirectLight;

    .line 18
    .line 19
    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/IndirectLight;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "Couldn\'t create IndirectLight"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public intensity(F)Lcom/google/android/filament/IndirectLight$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/IndirectLight;->e(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public irradiance(I[F)Lcom/google/android/filament/IndirectLight$Builder;
    .locals 2

    const/4 v0, 0x1

    const/4 v1, 0x3

    if-eq p1, v0, :cond_4

    const/4 v0, 0x2

    if-eq p1, v0, :cond_2

    if-ne p1, v1, :cond_1

    .line 1
    array-length v0, p2

    const/16 v1, 0x1b

    if-lt v0, v1, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    const-string p1, "3 bands SH, array must be at least 9 x float3"

    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 3
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "bands must be 1, 2 or 3"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 4
    :cond_2
    array-length v0, p2

    const/16 v1, 0xc

    if-lt v0, v1, :cond_3

    goto :goto_0

    .line 5
    :cond_3
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    const-string p1, "2 bands SH, array must be at least 4 x float3"

    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 6
    :cond_4
    array-length v0, p2

    if-lt v0, v1, :cond_5

    .line 7
    :goto_0
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/IndirectLight;->f(JI[F)V

    return-object p0

    .line 8
    :cond_5
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    const-string p1, "1 band SH, array must be at least 1 x float3"

    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public irradiance(Lcom/google/android/filament/Texture;)Lcom/google/android/filament/IndirectLight$Builder;
    .locals 4

    .line 9
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v2

    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/IndirectLight;->g(JJ)V

    return-object p0
.end method

.method public radiance(I[F)Lcom/google/android/filament/IndirectLight$Builder;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x3

    .line 3
    if-eq p1, v0, :cond_4

    .line 4
    .line 5
    const/4 v0, 0x2

    .line 6
    if-eq p1, v0, :cond_2

    .line 7
    .line 8
    if-ne p1, v1, :cond_1

    .line 9
    .line 10
    array-length v0, p2

    .line 11
    const/16 v1, 0x1b

    .line 12
    .line 13
    if-lt v0, v1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 17
    .line 18
    const-string p1, "3 bands SH, array must be at least 9 x float3"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 25
    .line 26
    const-string p1, "bands must be 1, 2 or 3"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_2
    array-length v0, p2

    .line 33
    const/16 v1, 0xc

    .line 34
    .line 35
    if-lt v0, v1, :cond_3

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_3
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 39
    .line 40
    const-string p1, "2 bands SH, array must be at least 4 x float3"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :cond_4
    array-length v0, p2

    .line 47
    if-lt v0, v1, :cond_5

    .line 48
    .line 49
    :goto_0
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    .line 50
    .line 51
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/IndirectLight;->h(JI[F)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_5
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 56
    .line 57
    const-string p1, "1 band SH, array must be at least 1 x float3"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public reflections(Lcom/google/android/filament/Texture;)Lcom/google/android/filament/IndirectLight$Builder;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/IndirectLight;->b(JJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public rotation([F)Lcom/google/android/filament/IndirectLight$Builder;
    .locals 11

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/IndirectLight$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    aget v2, p1, v2

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    aget v3, p1, v3

    .line 8
    .line 9
    const/4 v4, 0x2

    .line 10
    aget v4, p1, v4

    .line 11
    .line 12
    const/4 v5, 0x3

    .line 13
    aget v5, p1, v5

    .line 14
    .line 15
    const/4 v6, 0x4

    .line 16
    aget v6, p1, v6

    .line 17
    .line 18
    const/4 v7, 0x5

    .line 19
    aget v7, p1, v7

    .line 20
    .line 21
    const/4 v8, 0x6

    .line 22
    aget v8, p1, v8

    .line 23
    .line 24
    const/4 v9, 0x7

    .line 25
    aget v9, p1, v9

    .line 26
    .line 27
    const/16 v10, 0x8

    .line 28
    .line 29
    aget v10, p1, v10

    .line 30
    .line 31
    invoke-static/range {v0 .. v10}, Lcom/google/android/filament/IndirectLight;->i(JFFFFFFFFF)V

    .line 32
    .line 33
    .line 34
    return-object p0
.end method
