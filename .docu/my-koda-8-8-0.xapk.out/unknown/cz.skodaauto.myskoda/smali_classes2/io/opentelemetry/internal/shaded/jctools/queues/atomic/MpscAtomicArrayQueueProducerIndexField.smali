.class abstract Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;
.super Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueL1Pad;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueL1Pad<",
        "TE;>;"
    }
.end annotation


# static fields
.field private static final P_INDEX_UPDATER:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicLongFieldUpdater<",
            "Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private volatile producerIndex:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;

    .line 2
    .line 3
    const-string v1, "producerIndex"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->P_INDEX_UPDATER:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueL1Pad;-><init>(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final casProducerIndex(JJ)Z
    .locals 6

    .line 1
    sget-object v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->P_INDEX_UPDATER:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-wide v2, p1

    .line 5
    move-wide v4, p3

    .line 6
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final lvProducerIndex()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerIndexField;->producerIndex:J

    .line 2
    .line 3
    return-wide v0
.end method
