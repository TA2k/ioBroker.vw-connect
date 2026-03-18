.class public final Lio/opentelemetry/sdk/trace/internal/JcTools;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static capacity(Ljava/util/Queue;)J
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Queue<",
            "*>;)J"
        }
    .end annotation

    .line 1
    check-cast p0, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->capacity()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    int-to-long v0, p0

    .line 8
    return-wide v0
.end method

.method public static drain(Ljava/util/Queue;ILjava/util/function/Consumer;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Queue<",
            "TT;>;I",
            "Ljava/util/function/Consumer<",
            "TT;>;)I"
        }
    .end annotation

    .line 1
    check-cast p0, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;

    .line 2
    .line 3
    invoke-static {p2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    new-instance v0, Lgr/k;

    .line 7
    .line 8
    const/4 v1, 0x6

    .line 9
    invoke-direct {v0, p2, v1}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, v0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;->drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;I)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public static newFixedSizeQueue(I)Ljava/util/Queue;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(I)",
            "Ljava/util/Queue<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueue;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueue;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
