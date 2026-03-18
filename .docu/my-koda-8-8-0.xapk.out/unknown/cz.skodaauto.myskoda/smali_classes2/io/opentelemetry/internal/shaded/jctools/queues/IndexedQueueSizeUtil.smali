.class public final Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;
    }
.end annotation


# static fields
.field public static final IGNORE_PARITY_DIVISOR:I = 0x2

.field public static final PLAIN_DIVISOR:I = 0x1


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static isEmpty(Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;)Z
    .locals 4

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvConsumerIndex()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvProducerIndex()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    cmp-long p0, v0, v2

    .line 10
    .line 11
    if-ltz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public static sanitizedSize(IJ)I
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-gez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 v0, -0x1

    .line 10
    if-eq p0, v0, :cond_1

    .line 11
    .line 12
    int-to-long v0, p0

    .line 13
    cmp-long v0, p1, v0

    .line 14
    .line 15
    if-lez v0, :cond_1

    .line 16
    .line 17
    return p0

    .line 18
    :cond_1
    const-wide/32 v0, 0x7fffffff

    .line 19
    .line 20
    .line 21
    cmp-long p0, p1, v0

    .line 22
    .line 23
    if-lez p0, :cond_2

    .line 24
    .line 25
    const p0, 0x7fffffff

    .line 26
    .line 27
    .line 28
    return p0

    .line 29
    :cond_2
    long-to-int p0, p1

    .line 30
    return p0
.end method

.method public static size(Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;I)I
    .locals 6

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvConsumerIndex()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    :goto_0
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvProducerIndex()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvConsumerIndex()J

    .line 10
    .line 11
    .line 12
    move-result-wide v4

    .line 13
    cmp-long v0, v0, v4

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    sub-long/2addr v2, v4

    .line 18
    int-to-long v0, p1

    .line 19
    div-long/2addr v2, v0

    .line 20
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->capacity()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-static {p0, v2, v3}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil;->sanitizedSize(IJ)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0

    .line 29
    :cond_0
    move-wide v0, v4

    .line 30
    goto :goto_0
.end method
