.class public Lcom/google/android/filament/SkinningBuffer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/SkinningBuffer$Builder;
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
    iput-wide p1, p0, Lcom/google/android/filament/SkinningBuffer;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/SkinningBuffer;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/SkinningBuffer;->nBuilderBoneCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/SkinningBuffer;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic c(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/SkinningBuffer;->nBuilderInitialize(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/SkinningBuffer;->nCreateBuilder()J

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
    invoke-static {p0, p1}, Lcom/google/android/filament/SkinningBuffer;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBoneCount(JI)V
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderInitialize(JZ)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetBoneCount(J)I
.end method

.method private static native nSetBonesAsMatrices(JJLjava/nio/Buffer;III)I
.end method

.method private static native nSetBonesAsQuaternions(JJLjava/nio/Buffer;III)I
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/SkinningBuffer;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getBoneCount()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SkinningBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/SkinningBuffer;->nGetBoneCount(J)I

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
    iget-wide v0, p0, Lcom/google/android/filament/SkinningBuffer;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed IndexBuffer"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public setBonesAsMatrices(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;II)V
    .locals 8

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SkinningBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 8
    .line 9
    .line 10
    move-result v5

    .line 11
    move-object v4, p2

    .line 12
    move v6, p3

    .line 13
    move v7, p4

    .line 14
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/SkinningBuffer;->nSetBonesAsMatrices(JJLjava/nio/Buffer;III)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-ltz p0, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public setBonesAsQuaternions(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;II)V
    .locals 8

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SkinningBuffer;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 8
    .line 9
    .line 10
    move-result v5

    .line 11
    move-object v4, p2

    .line 12
    move v6, p3

    .line 13
    move v7, p4

    .line 14
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/SkinningBuffer;->nSetBonesAsQuaternions(JJLjava/nio/Buffer;III)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-ltz p0, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0
.end method
