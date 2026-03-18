.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;
.super Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Handle"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
        "Lio/opentelemetry/sdk/metrics/data/DoublePointData;",
        ">;"
    }
.end annotation


# instance fields
.field private final current:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Ljava/util/concurrent/atomic/AtomicLong;",
            ">;"
        }
    .end annotation
.end field

.field private final reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final valueBits:Ljava/util/concurrent/atomic/AtomicLong;


# direct methods
.method private constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 1

    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V

    .line 3
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->current:Ljava/util/concurrent/atomic/AtomicReference;

    .line 4
    new-instance p1, Ljava/util/concurrent/atomic/AtomicLong;

    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicLong;-><init>()V

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->valueBits:Ljava/util/concurrent/atomic/AtomicLong;

    .line 5
    sget-object p1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    if-ne p2, p1, :cond_0

    .line 6
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    invoke-direct {p1}, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;-><init>()V

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    return-void

    .line 7
    :cond_0
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    return-void
.end method


# virtual methods
.method public doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/DoublePointData;
    .locals 11
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;Z)",
            "Lio/opentelemetry/sdk/metrics/data/DoublePointData;"
        }
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->current:Ljava/util/concurrent/atomic/AtomicReference;

    if-eqz p7, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_0
    check-cast v0, Ljava/util/concurrent/atomic/AtomicLong;

    goto :goto_1

    :cond_0
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :goto_1
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    move-result-wide v8

    .line 4
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    if-eqz v2, :cond_1

    move-wide v3, p1

    move-wide v5, p3

    move-object/from16 v7, p5

    move-object/from16 v10, p6

    .line 5
    invoke-virtual/range {v2 .. v10}, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;->set(JJLio/opentelemetry/api/common/Attributes;DLjava/util/List;)V

    .line 6
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    return-object p0

    :cond_1
    move-wide v2, p1

    move-wide v4, p3

    move-object/from16 v6, p5

    move-wide v7, v8

    move-object/from16 v9, p6

    .line 7
    invoke-static/range {v2 .. v9}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableDoublePointData;->create(JJLio/opentelemetry/api/common/Attributes;DLjava/util/List;)Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 1
    invoke-virtual/range {p0 .. p7}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    move-result-object p0

    return-object p0
.end method

.method public doRecordDouble(D)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->valueBits:Ljava/util/concurrent/atomic/AtomicLong;

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    invoke-virtual {v0, p1, p2}, Ljava/util/concurrent/atomic/AtomicLong;->set(J)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->current:Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;->valueBits:Ljava/util/concurrent/atomic/AtomicLong;

    .line 13
    .line 14
    :cond_0
    const/4 p2, 0x0

    .line 15
    invoke-virtual {p1, p2, p0}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-eqz p2, :cond_1

    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    if-eqz p2, :cond_0

    .line 27
    .line 28
    return-void
.end method
