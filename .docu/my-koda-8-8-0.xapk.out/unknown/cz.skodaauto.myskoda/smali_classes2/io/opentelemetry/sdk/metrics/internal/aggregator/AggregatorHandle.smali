.class public abstract Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T::",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# static fields
.field private static final UNSUPPORTED_DOUBLE_MESSAGE:Ljava/lang/String; = "This aggregator does not support double values."

.field private static final UNSUPPORTED_LONG_MESSAGE:Ljava/lang/String; = "This aggregator does not support long values."


# instance fields
.field private final doubleReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final isDoubleType:Z

.field private final longReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private volatile valuesRecorded:Z


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->valuesRecorded:Z

    .line 6
    .line 7
    iput-boolean p2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->isDoubleType:Z

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doubleReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->longReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doubleReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 22
    .line 23
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->longReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 28
    .line 29
    return-void
.end method

.method private static throwUnsupportedIfNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0
    .param p0    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<S:",
            "Ljava/lang/Object;",
            ">(TS;",
            "Ljava/lang/String;",
            ")TS;"
        }
    .end annotation

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    return-object p0

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 5
    .line 6
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    throw p0
.end method


# virtual methods
.method public final aggregateThenMaybeReset(JJLio/opentelemetry/api/common/Attributes;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Z)TT;"
        }
    .end annotation

    .line 1
    if-eqz p6, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->valuesRecorded:Z

    .line 5
    .line 6
    :cond_0
    iget-boolean v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->isDoubleType:Z

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doubleReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 11
    .line 12
    const-string v1, "This aggregator does not support double values."

    .line 13
    .line 14
    invoke-static {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->throwUnsupportedIfNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 19
    .line 20
    invoke-interface {v0, p5}, Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;->collectAndResetDoubles(Lio/opentelemetry/api/common/Attributes;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    move-object v1, p0

    .line 25
    move-wide v2, p1

    .line 26
    move-wide v4, p3

    .line 27
    move-object v6, p5

    .line 28
    move v8, p6

    .line 29
    invoke-virtual/range {v1 .. v8}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_1
    move-object v0, p0

    .line 35
    move-wide v1, p1

    .line 36
    move-wide v3, p3

    .line 37
    move-object v5, p5

    .line 38
    move v7, p6

    .line 39
    iget-object p0, v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->longReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 40
    .line 41
    const-string p1, "This aggregator does not support long values."

    .line 42
    .line 43
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->throwUnsupportedIfNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 48
    .line 49
    invoke-interface {p0, v5}, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;->collectAndResetLongs(Lio/opentelemetry/api/common/Attributes;)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    invoke-virtual/range {v0 .. v7}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doAggregateThenMaybeResetLongs(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;Z)TT;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "This aggregator does not support double values."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public doAggregateThenMaybeResetLongs(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
            ">;Z)TT;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "This aggregator does not support long values."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public doRecordDouble(D)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "This aggregator does not support double values."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public doRecordLong(J)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "This aggregator does not support long values."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public hasRecordedValues()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->valuesRecorded:Z

    .line 2
    .line 3
    return p0
.end method

.method public final recordDouble(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doubleReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 2
    .line 3
    const-string v1, "This aggregator does not support double values."

    .line 4
    .line 5
    invoke-static {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->throwUnsupportedIfNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 10
    .line 11
    invoke-interface {v0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;->offerDoubleMeasurement(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doRecordDouble(D)V

    .line 15
    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->valuesRecorded:Z

    .line 19
    .line 20
    return-void
.end method

.method public recordLong(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->longReservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 2
    .line 3
    const-string v1, "This aggregator does not support long values."

    .line 4
    .line 5
    invoke-static {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->throwUnsupportedIfNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 10
    .line 11
    invoke-interface {v0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;->offerLongMeasurement(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->doRecordLong(J)V

    .line 15
    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->valuesRecorded:Z

    .line 19
    .line 20
    return-void
.end method
