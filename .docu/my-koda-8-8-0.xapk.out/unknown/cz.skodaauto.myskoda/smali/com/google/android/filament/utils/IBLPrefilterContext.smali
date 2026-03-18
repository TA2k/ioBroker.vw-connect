.class public Lcom/google/android/filament/utils/IBLPrefilterContext;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;,
        Lcom/google/android/filament/utils/IBLPrefilterContext$EquirectangularToCubemap;
    }
.end annotation


# instance fields
.field private mNativeObject:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/Engine;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nCreate(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/utils/IBLPrefilterContext;->mNativeObject:J

    .line 13
    .line 14
    const-wide/16 p0, 0x0

    .line 15
    .line 16
    cmp-long p0, v0, p0

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "Couldn\'t create IBLPrefilterContext"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public static bridge synthetic a(J)J
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nCreateEquirectHelper(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(J)J
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nCreateSpecularFilter(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic c(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nDestroyEquirectHelper(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nDestroySpecularFilter(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nEquirectHelperRun(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic f(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nSpecularFilterRun(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method private static native nCreate(J)J
.end method

.method private static native nCreateEquirectHelper(J)J
.end method

.method private static native nCreateSpecularFilter(J)J
.end method

.method private static native nDestroy(J)V
.end method

.method private static native nDestroyEquirectHelper(J)V
.end method

.method private static native nDestroySpecularFilter(J)V
.end method

.method private static native nEquirectHelperRun(JJ)J
.end method

.method private static native nSpecularFilterRun(JJ)J
.end method


# virtual methods
.method public destroy()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/IBLPrefilterContext;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->nDestroy(J)V

    .line 6
    .line 7
    .line 8
    const-wide/16 v0, 0x0

    .line 9
    .line 10
    iput-wide v0, p0, Lcom/google/android/filament/utils/IBLPrefilterContext;->mNativeObject:J

    .line 11
    .line 12
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/IBLPrefilterContext;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed IBLPrefilterContext"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method
