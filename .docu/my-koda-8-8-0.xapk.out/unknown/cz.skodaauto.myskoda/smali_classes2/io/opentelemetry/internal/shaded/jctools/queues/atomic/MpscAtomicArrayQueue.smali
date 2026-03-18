.class public Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueue;
.super Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueL3Pad;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueL3Pad<",
        "TE;>;"
    }
.end annotation


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueL3Pad;-><init>(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TE;>;)I"
        }
    .end annotation

    .line 17
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->capacity()I

    move-result v0

    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueue;->drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;I)I

    move-result p0

    return p0
.end method

.method public drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;I)I
    .locals 11
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TE;>;I)I"
        }
    .end annotation

    if-eqz p1, :cond_4

    if-ltz p2, :cond_3

    const/4 v0, 0x0

    if-nez p2, :cond_0

    return v0

    .line 1
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 2
    iget v2, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lpConsumerIndex()J

    move-result-wide v3

    :goto_0
    if-ge v0, p2, :cond_2

    int-to-long v5, v0

    add-long/2addr v5, v3

    int-to-long v7, v2

    .line 4
    invoke-static {v5, v6, v7, v8}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    move-result v7

    .line 5
    invoke-static {v1, v7}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    move-result-object v8

    if-nez v8, :cond_1

    return v0

    :cond_1
    const/4 v9, 0x0

    .line 6
    invoke-static {v1, v7, v9}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->spRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    const-wide/16 v9, 0x1

    add-long/2addr v5, v9

    .line 7
    invoke-virtual {p0, v5, v6}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->soConsumerIndex(J)V

    .line 8
    invoke-interface {p1, v8}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;->accept(Ljava/lang/Object;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    return p2

    .line 9
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "limit is negative: "

    .line 10
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 11
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 12
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "c is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;",
            ")V"
        }
    .end annotation

    .line 18
    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueueUtil;->drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V

    return-void
.end method

.method public final failFastOffer(Ljava/lang/Object;)I
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TE;)I"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    iget v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 4
    .line 5
    add-int/lit8 v1, v0, 0x1

    .line 6
    .line 7
    int-to-long v1, v1

    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->lvProducerIndex()J

    .line 9
    .line 10
    .line 11
    move-result-wide v3

    .line 12
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->lvProducerLimit()J

    .line 13
    .line 14
    .line 15
    move-result-wide v5

    .line 16
    cmp-long v5, v3, v5

    .line 17
    .line 18
    if-ltz v5, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lvConsumerIndex()J

    .line 21
    .line 22
    .line 23
    move-result-wide v5

    .line 24
    add-long/2addr v5, v1

    .line 25
    cmp-long v1, v3, v5

    .line 26
    .line 27
    if-ltz v1, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_0
    invoke-virtual {p0, v5, v6}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->soProducerLimit(J)V

    .line 32
    .line 33
    .line 34
    :cond_1
    const-wide/16 v1, 0x1

    .line 35
    .line 36
    add-long/2addr v1, v3

    .line 37
    invoke-virtual {p0, v3, v4, v1, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->casProducerIndex(JJ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    const/4 p0, -0x1

    .line 44
    return p0

    .line 45
    :cond_2
    int-to-long v0, v0

    .line 46
    invoke-static {v3, v4, v0, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-object p0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 51
    .line 52
    invoke-static {p0, v0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->soRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    const/4 p0, 0x0

    .line 56
    return p0

    .line 57
    :cond_3
    const/4 p0, 0x0

    .line 58
    throw p0
.end method

.method public fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;)I
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;)I"
        }
    .end annotation

    .line 19
    invoke-static {p0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueueUtil;->fillBounded(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;)I

    move-result p0

    return p0
.end method

.method public fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;I)I
    .locals 13
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;I)I"
        }
    .end annotation

    if-eqz p1, :cond_6

    if-ltz p2, :cond_5

    const/4 v0, 0x0

    if-nez p2, :cond_0

    return v0

    .line 1
    :cond_0
    iget v1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    add-int/lit8 v2, v1, 0x1

    int-to-long v2, v2

    .line 2
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->lvProducerLimit()J

    move-result-wide v4

    .line 3
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->lvProducerIndex()J

    move-result-wide v6

    sub-long v8, v4, v6

    const-wide/16 v10, 0x0

    cmp-long v12, v8, v10

    if-gtz v12, :cond_3

    .line 4
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lvConsumerIndex()J

    move-result-wide v4

    add-long/2addr v4, v2

    sub-long v8, v4, v6

    cmp-long v10, v8, v10

    if-gtz v10, :cond_2

    return v0

    .line 5
    :cond_2
    invoke-virtual {p0, v4, v5}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->soProducerLimit(J)V

    :cond_3
    long-to-int v8, v8

    .line 6
    invoke-static {v8, p2}, Ljava/lang/Math;->min(II)I

    move-result v8

    int-to-long v9, v8

    add-long/2addr v9, v6

    .line 7
    invoke-virtual {p0, v6, v7, v9, v10}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->casProducerIndex(JJ)Z

    move-result v9

    if-eqz v9, :cond_1

    .line 8
    iget-object p0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    :goto_0
    if-ge v0, v8, :cond_4

    int-to-long v2, v0

    add-long/2addr v2, v6

    int-to-long v4, v1

    .line 9
    invoke-static {v2, v3, v4, v5}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    move-result p2

    .line 10
    invoke-interface {p1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;->get()Ljava/lang/Object;

    move-result-object v2

    invoke-static {p0, p2, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->soRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_4
    return v8

    .line 11
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "limit is negative:"

    .line 12
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 14
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "supplier is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;",
            ")V"
        }
    .end annotation

    .line 20
    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueueUtil;->fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V

    return-void
.end method

.method public offer(Ljava/lang/Object;)Z
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TE;)Z"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    iget v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 4
    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->lvProducerLimit()J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->lvProducerIndex()J

    .line 10
    .line 11
    .line 12
    move-result-wide v3

    .line 13
    cmp-long v5, v3, v1

    .line 14
    .line 15
    const-wide/16 v6, 0x1

    .line 16
    .line 17
    if-ltz v5, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lvConsumerIndex()J

    .line 20
    .line 21
    .line 22
    move-result-wide v1

    .line 23
    int-to-long v8, v0

    .line 24
    add-long/2addr v1, v8

    .line 25
    add-long/2addr v1, v6

    .line 26
    cmp-long v5, v3, v1

    .line 27
    .line 28
    if-ltz v5, :cond_1

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return p0

    .line 32
    :cond_1
    invoke-virtual {p0, v1, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->soProducerLimit(J)V

    .line 33
    .line 34
    .line 35
    :cond_2
    add-long/2addr v6, v3

    .line 36
    invoke-virtual {p0, v3, v4, v6, v7}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->casProducerIndex(JJ)Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-eqz v5, :cond_0

    .line 41
    .line 42
    int-to-long v0, v0

    .line 43
    invoke-static {v3, v4, v0, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-object p0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 48
    .line 49
    invoke-static {p0, v0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->soRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    const/4 p0, 0x1

    .line 53
    return p0

    .line 54
    :cond_3
    const/4 p0, 0x0

    .line 55
    throw p0
.end method

.method public offerIfBelowThreshold(Ljava/lang/Object;I)Z
    .locals 11
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TE;I)Z"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    iget v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 4
    .line 5
    add-int/lit8 v1, v0, 0x1

    .line 6
    .line 7
    int-to-long v1, v1

    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->lvProducerLimit()J

    .line 9
    .line 10
    .line 11
    move-result-wide v3

    .line 12
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->lvProducerIndex()J

    .line 13
    .line 14
    .line 15
    move-result-wide v5

    .line 16
    sub-long v7, v3, v5

    .line 17
    .line 18
    sub-long v7, v1, v7

    .line 19
    .line 20
    int-to-long v9, p2

    .line 21
    cmp-long v7, v7, v9

    .line 22
    .line 23
    if-ltz v7, :cond_2

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lvConsumerIndex()J

    .line 26
    .line 27
    .line 28
    move-result-wide v3

    .line 29
    sub-long v7, v5, v3

    .line 30
    .line 31
    cmp-long v7, v7, v9

    .line 32
    .line 33
    if-ltz v7, :cond_1

    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    return p0

    .line 37
    :cond_1
    add-long/2addr v3, v1

    .line 38
    invoke-virtual {p0, v3, v4}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->soProducerLimit(J)V

    .line 39
    .line 40
    .line 41
    :cond_2
    const-wide/16 v7, 0x1

    .line 42
    .line 43
    add-long/2addr v7, v5

    .line 44
    invoke-virtual {p0, v5, v6, v7, v8}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->casProducerIndex(JJ)Z

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    if-eqz v7, :cond_0

    .line 49
    .line 50
    int-to-long v0, v0

    .line 51
    invoke-static {v5, v6, v0, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget-object p0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 56
    .line 57
    invoke-static {p0, p2, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->soRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const/4 p0, 0x1

    .line 61
    return p0

    .line 62
    :cond_3
    const/4 p0, 0x0

    .line 63
    throw p0
.end method

.method public peek()Ljava/lang/Object;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lpConsumerIndex()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    iget v3, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 8
    .line 9
    int-to-long v3, v3

    .line 10
    invoke-static {v1, v2, v3, v4}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    invoke-static {v0, v3}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    if-nez v4, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->lvProducerIndex()J

    .line 21
    .line 22
    .line 23
    move-result-wide v4

    .line 24
    cmp-long p0, v1, v4

    .line 25
    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    :cond_0
    invoke-static {v0, v3}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_1
    const/4 p0, 0x0

    .line 36
    return-object p0

    .line 37
    :cond_2
    return-object v4
.end method

.method public poll()Ljava/lang/Object;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lpConsumerIndex()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget v2, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 6
    .line 7
    int-to-long v2, v2

    .line 8
    invoke-static {v0, v1, v2, v3}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    iget-object v3, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 13
    .line 14
    invoke-static {v3, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    const/4 v5, 0x0

    .line 19
    if-nez v4, :cond_2

    .line 20
    .line 21
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->lvProducerIndex()J

    .line 22
    .line 23
    .line 24
    move-result-wide v6

    .line 25
    cmp-long v4, v0, v6

    .line 26
    .line 27
    if-eqz v4, :cond_1

    .line 28
    .line 29
    :cond_0
    invoke-static {v3, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    if-eqz v4, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    return-object v5

    .line 37
    :cond_2
    :goto_0
    invoke-static {v3, v2, v5}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->spRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    const-wide/16 v2, 0x1

    .line 41
    .line 42
    add-long/2addr v0, v2

    .line 43
    invoke-virtual {p0, v0, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->soConsumerIndex(J)V

    .line 44
    .line 45
    .line 46
    return-object v4
.end method

.method public relaxedOffer(Ljava/lang/Object;)Z
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TE;)Z"
        }
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueue;->offer(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public relaxedPeek()Ljava/lang/Object;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 4
    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lpConsumerIndex()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    int-to-long v4, v1

    .line 10
    invoke-static {v2, v3, v4, v5}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-static {v0, p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public relaxedPoll()Ljava/lang/Object;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->lpConsumerIndex()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    iget v3, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 8
    .line 9
    int-to-long v3, v3

    .line 10
    invoke-static {v1, v2, v3, v4}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    invoke-static {v0, v3}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    const/4 v5, 0x0

    .line 19
    if-nez v4, :cond_0

    .line 20
    .line 21
    return-object v5

    .line 22
    :cond_0
    invoke-static {v0, v3, v5}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->spRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;ILjava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    const-wide/16 v5, 0x1

    .line 26
    .line 27
    add-long/2addr v1, v5

    .line 28
    invoke-virtual {p0, v1, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueConsumerIndexField;->soConsumerIndex(J)V

    .line 29
    .line 30
    .line 31
    return-object v4
.end method

.method public weakOffer(Ljava/lang/Object;)I
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TE;)I"
        }
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueue;->failFastOffer(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
