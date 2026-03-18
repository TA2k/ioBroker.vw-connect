.class public Lcom/google/android/filament/Stream;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Stream$StreamType;,
        Lcom/google/android/filament/Stream$Builder;
    }
.end annotation


# static fields
.field private static final sStreamTypeValues:[Lcom/google/android/filament/Stream$StreamType;


# instance fields
.field private mNativeEngine:J

.field private mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/Stream$StreamType;->values()[Lcom/google/android/filament/Stream$StreamType;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/Stream;->sStreamTypeValues:[Lcom/google/android/filament/Stream$StreamType;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(JLcom/google/android/filament/Engine;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/Stream;->mNativeObject:J

    .line 5
    .line 6
    invoke-virtual {p3}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 7
    .line 8
    .line 9
    move-result-wide p1

    .line 10
    iput-wide p1, p0, Lcom/google/android/filament/Stream;->mNativeEngine:J

    .line 11
    .line 12
    return-void
.end method

.method public static bridge synthetic a(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Stream;->nBuilderBuild(JJ)J

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
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Stream;->nBuilderHeight(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(JLjava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/Stream;->nBuilderStreamSource(JLjava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Stream;->nBuilderWidth(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/Stream;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic f(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/Stream;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderHeight(JI)V
.end method

.method private static native nBuilderStreamSource(JLjava/lang/Object;)V
.end method

.method private static native nBuilderWidth(JI)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetStreamType(J)I
.end method

.method private static native nGetTimestamp(J)J
.end method

.method private static native nReadPixels(JJIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nSetAcquiredImage(JJLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Runnable;)V
.end method

.method private static native nSetDimensions(JII)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Stream;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Stream;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed Stream"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getStreamType()Lcom/google/android/filament/Stream$StreamType;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Stream;->sStreamTypeValues:[Lcom/google/android/filament/Stream$StreamType;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Stream;->nGetStreamType(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getTimestamp()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Stream;->nGetTimestamp(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public setAcquiredImage(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Runnable;)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lcom/google/android/filament/Stream;->mNativeEngine:J

    .line 6
    .line 7
    move-object v4, p1

    .line 8
    move-object v5, p2

    .line 9
    move-object v6, p3

    .line 10
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/Stream;->nSetAcquiredImage(JJLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public setDimensions(II)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/Stream;->nSetDimensions(JII)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
