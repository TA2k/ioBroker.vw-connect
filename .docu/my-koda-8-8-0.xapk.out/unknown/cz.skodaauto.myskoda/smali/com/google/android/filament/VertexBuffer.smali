.class public Lcom/google/android/filament/VertexBuffer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/VertexBuffer$Builder;,
        Lcom/google/android/filament/VertexBuffer$AttributeType;,
        Lcom/google/android/filament/VertexBuffer$VertexAttribute;
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
    iput-wide p1, p0, Lcom/google/android/filament/VertexBuffer;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/VertexBuffer;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a(JIIIII)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p6}, Lcom/google/android/filament/VertexBuffer;->nBuilderAttribute(JIIIII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/VertexBuffer;->nBuilderBufferCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/VertexBuffer;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic d(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/VertexBuffer;->nBuilderEnableBufferObjects(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JIZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/VertexBuffer;->nBuilderNormalized(JIZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/VertexBuffer;->nBuilderVertexCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/VertexBuffer;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic h(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/VertexBuffer;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderAttribute(JIIIII)V
.end method

.method private static native nBuilderBufferCount(JI)V
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderEnableBufferObjects(JZ)V
.end method

.method private static native nBuilderNormalized(JIZ)V
.end method

.method private static native nBuilderVertexCount(JI)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetVertexCount(J)I
.end method

.method private static native nSetBufferAt(JJILjava/nio/Buffer;IIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nSetBufferObjectAt(JJIJ)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/VertexBuffer;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed VertexBuffer"

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
    invoke-virtual {p0}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/VertexBuffer;->nGetVertexCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public setBufferAt(Lcom/google/android/filament/Engine;ILjava/nio/Buffer;)V
    .locals 8

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    .line 1
    invoke-virtual/range {v0 .. v7}, Lcom/google/android/filament/VertexBuffer;->setBufferAt(Lcom/google/android/filament/Engine;ILjava/nio/Buffer;IILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public setBufferAt(Lcom/google/android/filament/Engine;ILjava/nio/Buffer;II)V
    .locals 8

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    move v4, p4

    move v5, p5

    .line 2
    invoke-virtual/range {v0 .. v7}, Lcom/google/android/filament/VertexBuffer;->setBufferAt(Lcom/google/android/filament/Engine;ILjava/nio/Buffer;IILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public setBufferAt(Lcom/google/android/filament/Engine;ILjava/nio/Buffer;IILjava/lang/Object;Ljava/lang/Runnable;)V
    .locals 11

    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v2

    .line 4
    invoke-virtual {p3}, Ljava/nio/Buffer;->remaining()I

    move-result v6

    if-nez p5, :cond_0

    .line 5
    invoke-virtual {p3}, Ljava/nio/Buffer;->remaining()I

    move-result p0

    move v8, p0

    :goto_0
    move v4, p2

    move-object v5, p3

    move v7, p4

    move-object/from16 v9, p6

    move-object/from16 v10, p7

    goto :goto_1

    :cond_0
    move/from16 v8, p5

    goto :goto_0

    .line 6
    :goto_1
    invoke-static/range {v0 .. v10}, Lcom/google/android/filament/VertexBuffer;->nSetBufferAt(JJILjava/nio/Buffer;IIILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result p0

    if-ltz p0, :cond_1

    return-void

    .line 7
    :cond_1
    new-instance p0, Ljava/nio/BufferOverflowException;

    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw p0
.end method

.method public setBufferObjectAt(Lcom/google/android/filament/Engine;ILcom/google/android/filament/BufferObject;)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-virtual {p3}, Lcom/google/android/filament/BufferObject;->getNativeObject()J

    .line 10
    .line 11
    .line 12
    move-result-wide v5

    .line 13
    move v4, p2

    .line 14
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/VertexBuffer;->nSetBufferObjectAt(JJIJ)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
