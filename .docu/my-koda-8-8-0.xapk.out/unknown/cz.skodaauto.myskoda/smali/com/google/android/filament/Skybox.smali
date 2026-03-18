.class public Lcom/google/android/filament/Skybox;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Skybox$Builder;
    }
.end annotation


# instance fields
.field private mNativeObject:J


# direct methods
.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/Skybox;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method public static bridge synthetic a(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Skybox;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(JFFFF)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Lcom/google/android/filament/Skybox;->nBuilderColor(JFFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Skybox;->nBuilderEnvironment(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/Skybox;->nBuilderIntensity(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/Skybox;->nBuilderShowSun(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/Skybox;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic g(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/Skybox;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderColor(JFFFF)V
.end method

.method private static native nBuilderEnvironment(JJ)V
.end method

.method private static native nBuilderIntensity(JF)V
.end method

.method private static native nBuilderShowSun(JZ)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetIntensity(J)F
.end method

.method private static native nGetLayerMask(J)I
.end method

.method private static native nGetTexture(J)J
.end method

.method private static native nSetColor(JFFFF)V
.end method

.method private static native nSetLayerMask(JII)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Skybox;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getIntensity()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Skybox;->nGetIntensity(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getLayerMask()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Skybox;->nGetLayerMask(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Skybox;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed Skybox"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getTexture()Lcom/google/android/filament/Texture;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Skybox;->nGetTexture(J)J

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

.method public setColor(FFFF)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    move-result-wide v0

    move v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Skybox;->nSetColor(JFFFF)V

    return-void
.end method

.method public setColor([F)V
    .locals 6

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    move-result-wide v0

    const/4 p0, 0x0

    aget v2, p1, p0

    const/4 p0, 0x1

    aget v3, p1, p0

    const/4 p0, 0x2

    aget v4, p1, p0

    const/4 p0, 0x3

    aget v5, p1, p0

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Skybox;->nSetColor(JFFFF)V

    return-void
.end method

.method public setLayerMask(II)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

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
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Skybox;->nSetLayerMask(JII)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
