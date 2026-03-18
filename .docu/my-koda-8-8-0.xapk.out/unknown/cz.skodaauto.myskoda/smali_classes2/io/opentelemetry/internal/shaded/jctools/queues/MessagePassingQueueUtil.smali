.class public final Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueueUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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

.method public static drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TE;>;)I"
        }
    .end annotation

    if-eqz p1, :cond_1

    const/4 v0, 0x0

    .line 11
    :goto_0
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->relaxedPoll()Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_0

    add-int/lit8 v0, v0, 0x1

    .line 12
    invoke-interface {p1, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;->accept(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    return v0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "c is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;I)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TE;>;I)I"
        }
    .end annotation

    if-eqz p1, :cond_3

    if-ltz p2, :cond_2

    const/4 v0, 0x0

    if-nez p2, :cond_0

    return v0

    :cond_0
    :goto_0
    if-ge v0, p2, :cond_1

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->relaxedPoll()Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_1

    .line 2
    invoke-interface {p1, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;->accept(Ljava/lang/Object;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return v0

    .line 3
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "limit is negative: "

    .line 4
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 5
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 6
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "c is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;",
            ")V"
        }
    .end annotation

    if-eqz p1, :cond_4

    if-eqz p2, :cond_3

    if-eqz p3, :cond_2

    const/4 v0, 0x0

    :goto_0
    move v1, v0

    .line 14
    :goto_1
    invoke-interface {p3}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;->keepRunning()Z

    move-result v2

    if-eqz v2, :cond_1

    .line 15
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->relaxedPoll()Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_0

    .line 16
    invoke-interface {p2, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;->idle(I)I

    move-result v1

    goto :goto_1

    .line 17
    :cond_0
    invoke-interface {p1, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;->accept(Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    return-void

    .line 18
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "exit condition is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 19
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "wait is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 20
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "c is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;",
            ")V"
        }
    .end annotation

    .line 1
    if-eqz p2, :cond_3

    .line 2
    .line 3
    if-eqz p3, :cond_2

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    :cond_0
    move v1, v0

    .line 7
    :goto_0
    invoke-interface {p3}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;->keepRunning()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    sget v2, Lio/opentelemetry/internal/shaded/jctools/util/PortableJvmInfo;->RECOMENDED_OFFER_BATCH:I

    .line 14
    .line 15
    invoke-interface {p0, p1, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;I)I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    invoke-interface {p2, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;->idle(I)I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    return-void

    .line 27
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    const-string p1, "exit condition is null"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 36
    .line 37
    const-string p1, "waiter is null"

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public static fillBounded(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;)I"
        }
    .end annotation

    .line 1
    sget v0, Lio/opentelemetry/internal/shaded/jctools/util/PortableJvmInfo;->RECOMENDED_OFFER_BATCH:I

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->capacity()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-static {p0, p1, v0, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueueUtil;->fillInBatchesToLimit(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;II)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public static fillInBatchesToLimit(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;II)I
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;II)I"
        }
    .end annotation

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    :cond_0
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;I)I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    if-nez v2, :cond_1

    .line 8
    .line 9
    long-to-int p0, v0

    .line 10
    return p0

    .line 11
    :cond_1
    int-to-long v2, v2

    .line 12
    add-long/2addr v0, v2

    .line 13
    int-to-long v2, p3

    .line 14
    cmp-long v2, v0, v2

    .line 15
    .line 16
    if-lez v2, :cond_0

    .line 17
    .line 18
    long-to-int p0, v0

    .line 19
    return p0
.end method

.method public static fillUnbounded(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
            "TE;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TE;>;)I"
        }
    .end annotation

    .line 1
    sget v0, Lio/opentelemetry/internal/shaded/jctools/util/PortableJvmInfo;->RECOMENDED_OFFER_BATCH:I

    .line 2
    .line 3
    const/16 v1, 0x1000

    .line 4
    .line 5
    invoke-static {p0, p1, v0, v1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueueUtil;->fillInBatchesToLimit(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;II)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
