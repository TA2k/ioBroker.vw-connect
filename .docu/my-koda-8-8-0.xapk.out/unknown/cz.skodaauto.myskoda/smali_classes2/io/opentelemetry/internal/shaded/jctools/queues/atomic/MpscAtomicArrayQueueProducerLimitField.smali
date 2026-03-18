.class abstract Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;
.super Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueMidPad;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueMidPad<",
        "TE;>;"
    }
.end annotation


# static fields
.field private static final P_LIMIT_UPDATER:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicLongFieldUpdater<",
            "Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private volatile producerLimit:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;

    .line 2
    .line 3
    const-string v1, "producerLimit"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->P_LIMIT_UPDATER:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueMidPad;-><init>(I)V

    .line 2
    .line 3
    .line 4
    int-to-long v0, p1

    .line 5
    iput-wide v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->producerLimit:J

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final lvProducerLimit()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->producerLimit:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final soProducerLimit(J)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/internal/shaded/jctools/queues/atomic/MpscAtomicArrayQueueProducerLimitField;->P_LIMIT_UPDATER:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0, p1, p2}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->lazySet(Ljava/lang/Object;J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
