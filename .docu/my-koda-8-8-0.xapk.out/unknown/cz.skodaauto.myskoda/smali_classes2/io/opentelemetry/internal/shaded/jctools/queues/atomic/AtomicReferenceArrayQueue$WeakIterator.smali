.class Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "WeakIterator"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/Iterator<",
        "TE;>;"
    }
.end annotation


# instance fields
.field private final buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReferenceArray<",
            "TE;>;"
        }
    .end annotation
.end field

.field private final mask:I

.field private nextElement:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TE;"
        }
    .end annotation
.end field

.field private nextIndex:J

.field private final pIndex:J


# direct methods
.method public constructor <init>(JJILjava/util/concurrent/atomic/AtomicReferenceArray;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJI",
            "Ljava/util/concurrent/atomic/AtomicReferenceArray<",
            "TE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextIndex:J

    .line 5
    .line 6
    iput-wide p3, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->pIndex:J

    .line 7
    .line 8
    iput p5, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->mask:I

    .line 9
    .line 10
    iput-object p6, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 11
    .line 12
    invoke-direct {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->getNext()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextElement:Ljava/lang/Object;

    .line 17
    .line 18
    return-void
.end method

.method private getNext()Ljava/lang/Object;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    iget v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->mask:I

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->buffer:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 4
    .line 5
    :cond_0
    iget-wide v2, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextIndex:J

    .line 6
    .line 7
    iget-wide v4, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->pIndex:J

    .line 8
    .line 9
    cmp-long v4, v2, v4

    .line 10
    .line 11
    if-gez v4, :cond_1

    .line 12
    .line 13
    const-wide/16 v4, 0x1

    .line 14
    .line 15
    add-long/2addr v4, v2

    .line 16
    iput-wide v4, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextIndex:J

    .line 17
    .line 18
    int-to-long v4, v0

    .line 19
    invoke-static {v2, v3, v4, v5}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->calcCircularRefElementOffset(JJ)I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    invoke-static {v1, v2}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicQueueUtil;->lvRefElement(Ljava/util/concurrent/atomic/AtomicReferenceArray;I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    return-object v2

    .line 30
    :cond_1
    const/4 p0, 0x0

    .line 31
    return-object p0
.end method


# virtual methods
.method public hasNext()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextElement:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public next()Ljava/lang/Object;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextElement:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-direct {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->getNext()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iput-object v1, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/AtomicReferenceArrayQueue$WeakIterator;->nextElement:Ljava/lang/Object;

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public remove()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "remove"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
