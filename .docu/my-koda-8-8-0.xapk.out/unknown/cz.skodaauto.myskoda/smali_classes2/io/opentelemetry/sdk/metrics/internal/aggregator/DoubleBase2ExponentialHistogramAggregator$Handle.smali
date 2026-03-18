.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;
.super Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Handle"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
        "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;",
        ">;"
    }
.end annotation


# instance fields
.field private count:J

.field private currentScale:I

.field private max:D

.field private final maxBuckets:I

.field private final maxScale:I

.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private min:D

.field private negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private sum:D

.field private zeroCount:J


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;IILio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V

    .line 3
    .line 4
    .line 5
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->maxBuckets:I

    .line 6
    .line 7
    iput p3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->maxScale:I

    .line 8
    .line 9
    const-wide/16 p1, 0x0

    .line 10
    .line 11
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->sum:D

    .line 12
    .line 13
    const-wide/16 p1, 0x0

    .line 14
    .line 15
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->zeroCount:J

    .line 16
    .line 17
    const-wide v0, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->min:D

    .line 23
    .line 24
    const-wide/high16 v0, -0x4010000000000000L    # -1.0

    .line 25
    .line 26
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->max:D

    .line 27
    .line 28
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->count:J

    .line 29
    .line 30
    iput p3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    .line 31
    .line 32
    sget-object p1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 33
    .line 34
    if-ne p4, p1, :cond_0

    .line 35
    .line 36
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;

    .line 37
    .line 38
    invoke-direct {p1}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;-><init>()V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 p1, 0x0

    .line 43
    :goto_0
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;

    .line 44
    .line 45
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 46
    .line 47
    return-void
.end method

.method private resolveBuckets(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;IZLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 6
    .param p1    # Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {p2}, Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;->get(I)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    if-nez p4, :cond_1

    .line 9
    .line 10
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->copy()Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    goto :goto_2

    .line 15
    :cond_1
    instance-of p2, p4, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;

    .line 16
    .line 17
    if-eqz p2, :cond_2

    .line 18
    .line 19
    check-cast p4, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;

    .line 20
    .line 21
    :goto_0
    move-object v0, p4

    .line 22
    goto :goto_1

    .line 23
    :cond_2
    new-instance p4, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;

    .line 24
    .line 25
    invoke-direct {p4}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;-><init>()V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :goto_1
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->getReusableBucketCountsList()Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-virtual {p1, v5}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getBucketCountsIntoReusableList(Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getScale()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getOffset()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getTotalCount()J

    .line 45
    .line 46
    .line 47
    move-result-wide v3

    .line 48
    invoke-virtual/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->set(IIJLio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;

    .line 49
    .line 50
    .line 51
    move-object p2, v0

    .line 52
    :goto_2
    if-eqz p3, :cond_3

    .line 53
    .line 54
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->maxScale:I

    .line 55
    .line 56
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->clear(I)V

    .line 57
    .line 58
    .line 59
    :cond_3
    return-object p2
.end method


# virtual methods
.method public declared-synchronized doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;
    .locals 28
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;Z)",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;"
        }
    .end annotation

    move-object/from16 v1, p0

    move/from16 v0, p7

    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v2, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;

    const-wide/16 v5, 0x0

    if-nez v2, :cond_2

    .line 3
    iget v7, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    iget-wide v8, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->sum:D

    iget-wide v10, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->zeroCount:J

    iget-wide v12, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->count:J

    cmp-long v2, v12, v5

    move-wide v13, v12

    if-lez v2, :cond_0

    const/4 v12, 0x1

    goto :goto_0

    :cond_0
    const/4 v12, 0x0

    :goto_0
    iget-wide v3, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->min:D

    cmp-long v2, v13, v5

    if-lez v2, :cond_1

    const/4 v15, 0x1

    goto :goto_1

    :cond_1
    const/4 v15, 0x0

    :goto_1
    iget-wide v13, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->max:D

    iget-object v2, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    move-wide/from16 v26, v5

    const/4 v5, 0x0

    .line 4
    invoke-direct {v1, v2, v7, v0, v5}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->resolveBuckets(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;IZLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v18

    iget-object v2, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    iget v6, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    .line 5
    invoke-direct {v1, v2, v6, v0, v5}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->resolveBuckets(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;IZLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v19

    move-wide/from16 v20, p1

    move-wide/from16 v22, p3

    move-object/from16 v24, p5

    move-object/from16 v25, p6

    move-wide/from16 v16, v13

    move-wide v13, v3

    .line 6
    invoke-static/range {v7 .. v25}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramPointData;->create(IDJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    move-result-object v2

    goto :goto_5

    :catchall_0
    move-exception v0

    goto/16 :goto_6

    :cond_2
    move-wide/from16 v26, v5

    .line 7
    iget v3, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    iget-wide v4, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->sum:D

    iget-wide v6, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->zeroCount:J

    iget-wide v8, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->count:J

    cmp-long v10, v8, v26

    if-lez v10, :cond_3

    move-wide v9, v8

    const/4 v8, 0x1

    goto :goto_2

    :cond_3
    move-wide v9, v8

    const/4 v8, 0x0

    :goto_2
    iget-wide v11, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->min:D

    cmp-long v9, v9, v26

    if-lez v9, :cond_4

    const/4 v15, 0x1

    :goto_3
    move-wide v9, v11

    goto :goto_4

    :cond_4
    const/4 v15, 0x0

    goto :goto_3

    :goto_4
    iget-wide v12, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->max:D

    iget-object v11, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 8
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v14

    .line 9
    invoke-direct {v1, v11, v3, v0, v14}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->resolveBuckets(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;IZLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v14

    iget-object v11, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    move-object/from16 v16, v2

    iget v2, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    move/from16 v17, v3

    iget-object v3, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->reusablePoint:Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;

    .line 10
    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v3

    .line 11
    invoke-direct {v1, v11, v2, v0, v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->resolveBuckets(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;IZLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v2

    move-wide/from16 v18, p3

    move-object/from16 v20, p5

    move-object/from16 v21, p6

    move v11, v15

    move/from16 v3, v17

    move-object v15, v2

    move-object/from16 v2, v16

    move-wide/from16 v16, p1

    .line 12
    invoke-virtual/range {v2 .. v21}, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->set(IDJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    move-result-object v2

    :goto_5
    if-eqz v0, :cond_5

    const-wide/16 v3, 0x0

    .line 13
    iput-wide v3, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->sum:D

    const-wide/16 v3, 0x0

    .line 14
    iput-wide v3, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->zeroCount:J

    const-wide v5, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 15
    iput-wide v5, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->min:D

    const-wide/high16 v5, -0x4010000000000000L    # -1.0

    .line 16
    iput-wide v5, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->max:D

    .line 17
    iput-wide v3, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->count:J

    .line 18
    iget v0, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->maxScale:I

    iput v0, v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    :cond_5
    monitor-exit p0

    return-object v2

    :goto_6
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public bridge synthetic doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 1
    invoke-virtual/range {p0 .. p7}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    move-result-object p0

    return-object p0
.end method

.method public declared-synchronized doRecordDouble(D)V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-static {p1, p2}, Ljava/lang/Double;->isFinite(D)Z

    .line 3
    .line 4
    .line 5
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    monitor-exit p0

    .line 9
    return-void

    .line 10
    :cond_0
    :try_start_1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->sum:D

    .line 11
    .line 12
    add-double/2addr v0, p1

    .line 13
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->sum:D

    .line 14
    .line 15
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->min:D

    .line 16
    .line 17
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->min(DD)D

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->min:D

    .line 22
    .line 23
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->max:D

    .line 24
    .line 25
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->max(DD)D

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->max:D

    .line 30
    .line 31
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->count:J

    .line 32
    .line 33
    const-wide/16 v2, 0x1

    .line 34
    .line 35
    add-long/2addr v0, v2

    .line 36
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->count:J

    .line 37
    .line 38
    const-wide/16 v0, 0x0

    .line 39
    .line 40
    invoke-static {p1, p2, v0, v1}, Ljava/lang/Double;->compare(DD)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_1

    .line 45
    .line 46
    iget-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->zeroCount:J

    .line 47
    .line 48
    add-long/2addr p1, v2

    .line 49
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->zeroCount:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 50
    .line 51
    monitor-exit p0

    .line 52
    return-void

    .line 53
    :catchall_0
    move-exception p1

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    if-lez v0, :cond_3

    .line 56
    .line 57
    :try_start_2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 58
    .line 59
    if-nez v0, :cond_2

    .line 60
    .line 61
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 62
    .line 63
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    .line 64
    .line 65
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->maxBuckets:I

    .line 66
    .line 67
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 68
    .line 69
    invoke-direct {v0, v1, v2, v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;-><init>(IILio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 70
    .line 71
    .line 72
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 73
    .line 74
    :cond_2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 78
    .line 79
    if-nez v0, :cond_4

    .line 80
    .line 81
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 82
    .line 83
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    .line 84
    .line 85
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->maxBuckets:I

    .line 86
    .line 87
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 88
    .line 89
    invoke-direct {v0, v1, v2, v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;-><init>(IILio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 90
    .line 91
    .line 92
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 93
    .line 94
    :cond_4
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 95
    .line 96
    :goto_0
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->record(D)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-nez v1, :cond_5

    .line 101
    .line 102
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getScaleReduction(D)I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    invoke-virtual {p0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->downScale(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->record(D)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 110
    .line 111
    .line 112
    :cond_5
    monitor-exit p0

    .line 113
    return-void

    .line 114
    :goto_1
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 115
    throw p1
.end method

.method public downScale(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->downscale(I)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->positiveBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 9
    .line 10
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getScale()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    .line 15
    .line 16
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->downscale(I)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->negativeBuckets:Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 24
    .line 25
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getScale()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;->currentScale:I

    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public recordLong(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    long-to-double p1, p1

    .line 2
    invoke-virtual {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->recordDouble(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method
