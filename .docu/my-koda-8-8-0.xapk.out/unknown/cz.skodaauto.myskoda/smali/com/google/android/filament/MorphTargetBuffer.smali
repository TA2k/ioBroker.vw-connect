.class public Lcom/google/android/filament/MorphTargetBuffer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/MorphTargetBuffer$Builder;
    }
.end annotation


# instance fields
.field private mNativeObject:J


# direct methods
.method private constructor <init>(J)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/MorphTargetBuffer;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/MorphTargetBuffer;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/MorphTargetBuffer;->nBuilderCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/MorphTargetBuffer;->nBuilderVertexCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/MorphTargetBuffer;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic e(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/MorphTargetBuffer;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderCount(JI)V
.end method

.method private static native nBuilderVertexCount(JI)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetCount(J)I
.end method

.method private static native nGetVertexCount(J)I
.end method

.method private static native nSetPositionsAt(JJI[FI)I
.end method

.method private static native nSetTangentsAt(JJI[SI)I
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getCount()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/MorphTargetBuffer;->nGetCount(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed MorphTargetBuffer"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getVertexCount()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/MorphTargetBuffer;->nGetVertexCount(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public setPositionsAt(Lcom/google/android/filament/Engine;I[FI)V
    .locals 7

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    move v4, p2

    .line 8
    move-object v5, p3

    .line 9
    move v6, p4

    .line 10
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MorphTargetBuffer;->nSetPositionsAt(JJI[FI)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-ltz p0, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0
.end method

.method public setTangentsAt(Lcom/google/android/filament/Engine;I[SI)V
    .locals 7

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/MorphTargetBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    move v4, p2

    .line 8
    move-object v5, p3

    .line 9
    move v6, p4

    .line 10
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/MorphTargetBuffer;->nSetTangentsAt(JJI[SI)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-ltz p0, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0
.end method
