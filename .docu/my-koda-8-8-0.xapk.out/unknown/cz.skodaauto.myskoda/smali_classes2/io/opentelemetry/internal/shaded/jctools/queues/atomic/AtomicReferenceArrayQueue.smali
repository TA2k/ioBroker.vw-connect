.class public abstract Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;
.super Ljava/util/AbstractQueue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;
.implements Lio/opentelemetry/internal/shaded/jctools/queues/QueueProgressIndicators;
.implements Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;
.implements Lio/opentelemetry/internal/shaded/jctools/queues/SupportsIterator;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/util/AbstractQueue<",
        "TE;>;",
        "Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;",
        "Lio/opentelemetry/internal/shaded/jctools/queues/QueueProgressIndicators;",
        "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue<",
        "TE;>;",
        "Lio/opentelemetry/internal/shaded/jctools/queues/SupportsIterator;"
    }
.end annotation


# instance fields
.field protected final buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReferenceArray<",
            "TE;>;"
        }
    .end annotation
.end field

.field protected final mask:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractQueue;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lio/opentelemetry/internal/shaded/jctools/util/Pow2;->roundToPowerOfTwo(I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    add-int/lit8 v0, p1, -0x1

    .line 9
    .line 10
    iput v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 11
    .line 12
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 13
    .line 14
    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final capacity()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 2
    .line 3
    add-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method

.method public clear()V
    .locals 1

    .line 1
    :goto_0
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->poll()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    return-void
.end method

.method public final currentConsumerIndex()J
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvConsumerIndex()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public final currentProducerIndex()J
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvProducerIndex()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil;->isEmpty(Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Iterator<",
            "TE;>;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvConsumerIndex()J

    .line 2
    .line 3
    .line 4
    move-result-wide v1

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;->lvProducerIndex()J

    .line 6
    .line 7
    .line 8
    move-result-wide v3

    .line 9
    new-instance v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;

    .line 10
    .line 11
    iget v5, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->mask:I

    .line 12
    .line 13
    iget-object v6, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 14
    .line 15
    invoke-direct/range {v0 .. v6}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;-><init>(JJILjava/util/concurrent/atomic/AtomicReferenceArray;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final size()I
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p0, v0}, Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil;->size(Lio/opentelemetry/internal/shaded/jctools/queues/IndexedQueueSizeUtil$IndexedQueue;I)I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
