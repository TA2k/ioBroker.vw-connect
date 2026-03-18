.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;
.super Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Handle"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
        "Lio/opentelemetry/sdk/metrics/data/LongPointData;",
        ">;"
    }
.end annotation


# static fields
.field private static final DEFAULT_VALUE:Ljava/lang/Long;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# instance fields
.field private final current:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private final reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V

    .line 3
    .line 4
    .line 5
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 6
    .line 7
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->DEFAULT_VALUE:Ljava/lang/Long;

    .line 8
    .line 9
    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->current:Ljava/util/concurrent/atomic/AtomicReference;

    .line 13
    .line 14
    sget-object p1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 15
    .line 16
    if-ne p2, p1, :cond_0

    .line 17
    .line 18
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    .line 19
    .line 20
    invoke-direct {p1}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    const/4 p1, 0x0

    .line 27
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public doAggregateThenMaybeResetLongs(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/LongPointData;
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
            ">;Z)",
            "Lio/opentelemetry/sdk/metrics/data/LongPointData;"
        }
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->current:Ljava/util/concurrent/atomic/AtomicReference;

    if-eqz p7, :cond_0

    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->DEFAULT_VALUE:Ljava/lang/Long;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_0
    check-cast v0, Ljava/lang/Long;

    goto :goto_1

    :cond_0
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    .line 3
    :goto_1
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    if-eqz v1, :cond_1

    .line 4
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v7

    move-wide v2, p1

    move-wide v4, p3

    move-object v6, p5

    move-object/from16 v9, p6

    .line 5
    invoke-virtual/range {v1 .. v9}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->set(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)V

    .line 6
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    return-object p0

    .line 7
    :cond_1
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v5

    move-wide v0, p1

    move-wide v2, p3

    move-object v4, p5

    move-object/from16 v7, p6

    .line 8
    invoke-static/range {v0 .. v7}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableLongPointData;->create(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)Lio/opentelemetry/sdk/metrics/data/LongPointData;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic doAggregateThenMaybeResetLongs(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 1
    invoke-virtual/range {p0 .. p7}, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->doAggregateThenMaybeResetLongs(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/LongPointData;

    move-result-object p0

    return-object p0
.end method

.method public doRecordLong(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongLastValueAggregator$Handle;->current:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
