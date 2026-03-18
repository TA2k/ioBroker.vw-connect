.class public Lcom/google/android/filament/SurfaceOrientation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/SurfaceOrientation$Builder;
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
    iput-wide p1, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/SurfaceOrientation;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a(J)J
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderBuild(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(JILjava/nio/Buffer;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p3, p2, p4}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderNormals(JLjava/nio/Buffer;II)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(JILjava/nio/Buffer;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p3, p2, p4}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderPositions(JLjava/nio/Buffer;II)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(JILjava/nio/Buffer;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p3, p2, p4}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderTangents(JLjava/nio/Buffer;II)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderTriangleCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(JLjava/nio/Buffer;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderTriangles16(JLjava/nio/Buffer;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(JLjava/nio/Buffer;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderTriangles32(JLjava/nio/Buffer;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic h(JILjava/nio/Buffer;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p3, p2, p4}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderUVs(JLjava/nio/Buffer;II)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/SurfaceOrientation;->nBuilderVertexCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic j()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/SurfaceOrientation;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic k(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/SurfaceOrientation;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(J)J
.end method

.method private static native nBuilderNormals(JLjava/nio/Buffer;II)V
.end method

.method private static native nBuilderPositions(JLjava/nio/Buffer;II)V
.end method

.method private static native nBuilderTangents(JLjava/nio/Buffer;II)V
.end method

.method private static native nBuilderTriangleCount(JI)V
.end method

.method private static native nBuilderTriangles16(JLjava/nio/Buffer;I)V
.end method

.method private static native nBuilderTriangles32(JLjava/nio/Buffer;I)V
.end method

.method private static native nBuilderUVs(JLjava/nio/Buffer;II)V
.end method

.method private static native nBuilderVertexCount(JI)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroy(J)V
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetQuatsAsFloat(JLjava/nio/Buffer;I)V
.end method

.method private static native nGetQuatsAsHalf(JLjava/nio/Buffer;I)V
.end method

.method private static native nGetQuatsAsShort(JLjava/nio/Buffer;I)V
.end method

.method private static native nGetVertexCount(J)I
.end method


# virtual methods
.method public destroy()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/SurfaceOrientation;->nDestroy(J)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    .line 9
    .line 10
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed SurfaceOrientation"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getQuatsAsFloat(Ljava/nio/Buffer;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {v0, v1, p1, p0}, Lcom/google/android/filament/SurfaceOrientation;->nGetQuatsAsFloat(JLjava/nio/Buffer;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public getQuatsAsHalf(Ljava/nio/Buffer;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {v0, v1, p1, p0}, Lcom/google/android/filament/SurfaceOrientation;->nGetQuatsAsHalf(JLjava/nio/Buffer;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public getQuatsAsShort(Ljava/nio/Buffer;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {v0, v1, p1, p0}, Lcom/google/android/filament/SurfaceOrientation;->nGetQuatsAsShort(JLjava/nio/Buffer;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public getVertexCount()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SurfaceOrientation;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/SurfaceOrientation;->nGetVertexCount(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
