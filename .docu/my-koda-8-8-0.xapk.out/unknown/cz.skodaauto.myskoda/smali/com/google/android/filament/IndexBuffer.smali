.class public Lcom/google/android/filament/IndexBuffer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/IndexBuffer$Builder;
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
    iput-wide p1, p0, Lcom/google/android/filament/IndexBuffer;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/IndexBuffer;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/IndexBuffer;->nBuilderBufferType(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/IndexBuffer;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic c(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/IndexBuffer;->nBuilderIndexCount(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/IndexBuffer;->nCreateBuilder()J

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
    invoke-static {p0, p1}, Lcom/google/android/filament/IndexBuffer;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBufferType(JI)V
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderIndexCount(JI)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetIndexCount(J)I
.end method

.method private static native nSetBuffer(JJLjava/nio/Buffer;IIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/IndexBuffer;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getIndexCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/IndexBuffer;->nGetIndexCount(J)I

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
    iget-wide v0, p0, Lcom/google/android/filament/IndexBuffer;->mNativeObject:J

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

.method public setBuffer(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    .line 1
    invoke-virtual/range {v0 .. v6}, Lcom/google/android/filament/IndexBuffer;->setBuffer(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;IILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public setBuffer(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;II)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move v4, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lcom/google/android/filament/IndexBuffer;->setBuffer(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;IILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public setBuffer(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;IILjava/lang/Object;Ljava/lang/Runnable;)V
    .locals 10

    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    move-result-wide v0

    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v2

    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    move-result v5

    if-nez p4, :cond_0

    .line 4
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    move-result p4

    :cond_0
    move-object v4, p2

    move v6, p3

    move v7, p4

    move-object v8, p5

    move-object/from16 v9, p6

    .line 5
    invoke-static/range {v0 .. v9}, Lcom/google/android/filament/IndexBuffer;->nSetBuffer(JJLjava/nio/Buffer;IIILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result p0

    if-ltz p0, :cond_1

    return-void

    .line 6
    :cond_1
    new-instance p0, Ljava/nio/BufferOverflowException;

    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw p0
.end method
