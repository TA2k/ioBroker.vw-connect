.class public Lcom/google/android/filament/ToneMapper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/ToneMapper$Generic;,
        Lcom/google/android/filament/ToneMapper$Agx;,
        Lcom/google/android/filament/ToneMapper$PBRNeutralToneMapper;,
        Lcom/google/android/filament/ToneMapper$Filmic;,
        Lcom/google/android/filament/ToneMapper$ACESLegacy;,
        Lcom/google/android/filament/ToneMapper$ACES;,
        Lcom/google/android/filament/ToneMapper$Linear;
    }
.end annotation


# instance fields
.field private final mNativeObject:J


# direct methods
.method private constructor <init>(J)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lcom/google/android/filament/ToneMapper;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/ToneMapper;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/ToneMapper;->nCreateACESLegacyToneMapper()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic b()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/ToneMapper;->nCreateACESToneMapper()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic c(I)J
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/ToneMapper;->nCreateAgxToneMapper(I)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic d()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/ToneMapper;->nCreateFilmicToneMapper()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic e(FFFF)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/ToneMapper;->nCreateGenericToneMapper(FFFF)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic f()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/ToneMapper;->nCreateLinearToneMapper()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic g()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/ToneMapper;->nCreatePBRNeutralToneMapper()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic h(J)F
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/ToneMapper;->nGenericGetContrast(J)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic i(J)F
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/ToneMapper;->nGenericGetHdrMax(J)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic j(J)F
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/ToneMapper;->nGenericGetMidGrayIn(J)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic k(J)F
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/ToneMapper;->nGenericGetMidGrayOut(J)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic l(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ToneMapper;->nGenericSetContrast(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic m(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ToneMapper;->nGenericSetHdrMax(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic n(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ToneMapper;->nGenericSetMidGrayIn(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nCreateACESLegacyToneMapper()J
.end method

.method private static native nCreateACESToneMapper()J
.end method

.method private static native nCreateAgxToneMapper(I)J
.end method

.method private static native nCreateFilmicToneMapper()J
.end method

.method private static native nCreateGenericToneMapper(FFFF)J
.end method

.method private static native nCreateLinearToneMapper()J
.end method

.method private static native nCreatePBRNeutralToneMapper()J
.end method

.method private static native nDestroyToneMapper(J)V
.end method

.method private static native nGenericGetContrast(J)F
.end method

.method private static native nGenericGetHdrMax(J)F
.end method

.method private static native nGenericGetMidGrayIn(J)F
.end method

.method private static native nGenericGetMidGrayOut(J)F
.end method

.method private static native nGenericSetContrast(JF)V
.end method

.method private static native nGenericSetHdrMax(JF)V
.end method

.method private static native nGenericSetMidGrayIn(JF)V
.end method

.method private static native nGenericSetMidGrayOut(JF)V
.end method

.method public static bridge synthetic o(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/ToneMapper;->nGenericSetMidGrayOut(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public finalize()V
    .locals 3

    .line 1
    :try_start_0
    invoke-super {p0}, Ljava/lang/Object;->finalize()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 2
    .line 3
    .line 4
    iget-wide v0, p0, Lcom/google/android/filament/ToneMapper;->mNativeObject:J

    .line 5
    .line 6
    invoke-static {v0, v1}, Lcom/google/android/filament/ToneMapper;->nDestroyToneMapper(J)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception v0

    .line 11
    iget-wide v1, p0, Lcom/google/android/filament/ToneMapper;->mNativeObject:J

    .line 12
    .line 13
    invoke-static {v1, v2}, Lcom/google/android/filament/ToneMapper;->nDestroyToneMapper(J)V

    .line 14
    .line 15
    .line 16
    throw v0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/ToneMapper;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed ToneMapper"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method
