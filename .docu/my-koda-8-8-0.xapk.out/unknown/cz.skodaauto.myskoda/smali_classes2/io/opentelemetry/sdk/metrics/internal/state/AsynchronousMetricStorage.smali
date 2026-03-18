.class public final Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T::",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;"
    }
.end annotation


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

.field private final aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
            "TT;>;"
        }
    .end annotation
.end field

.field private final aggregatorHandles:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

.field private volatile enabled:Z

.field private epochNanos:J

.field private final handleBuilder:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final handleReleaser:Ljava/util/function/BiConsumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private lastPoints:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/api/common/Attributes;",
            "TT;>;"
        }
    .end annotation
.end field

.field private final maxCardinality:I

.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private final metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

.field private final pointReleaser:Ljava/util/function/BiConsumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/api/common/Attributes;",
            "TT;>;"
        }
    .end annotation
.end field

.field private final registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

.field private final reusableHandlesPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool<",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final reusablePointsList:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "TT;>;"
        }
    .end annotation
.end field

.field private reusablePointsMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/api/common/Attributes;",
            "TT;>;"
        }
    .end annotation
.end field

.field private final reusablePointsPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool<",
            "TT;>;"
        }
    .end annotation
.end field

.field private startEpochNanos:J

.field private final throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;IZ)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
            "TT;>;",
            "Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;",
            "IZ)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 5
    .line 6
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->logger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsList:Ljava/util/List;

    .line 19
    .line 20
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;

    .line 21
    .line 22
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsMap:Ljava/util/Map;

    .line 26
    .line 27
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 28
    .line 29
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 30
    .line 31
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-interface {v0, p2}, Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;->getAggregationTemporality(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 48
    .line 49
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 58
    .line 59
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 60
    .line 61
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 62
    .line 63
    add-int/lit8 p5, p5, -0x1

    .line 64
    .line 65
    iput p5, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->maxCardinality:I

    .line 66
    .line 67
    iput-boolean p6, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->enabled:Z

    .line 68
    .line 69
    new-instance p2, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 70
    .line 71
    invoke-static {p3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    new-instance p4, Lio/opentelemetry/sdk/metrics/internal/state/a;

    .line 75
    .line 76
    const/4 p5, 0x0

    .line 77
    invoke-direct {p4, p3, p5}, Lio/opentelemetry/sdk/metrics/internal/state/a;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;I)V

    .line 78
    .line 79
    .line 80
    invoke-direct {p2, p4}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;-><init>(Ljava/util/function/Supplier;)V

    .line 81
    .line 82
    .line 83
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 84
    .line 85
    new-instance p2, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 86
    .line 87
    new-instance p4, Lio/opentelemetry/sdk/metrics/internal/state/a;

    .line 88
    .line 89
    const/4 p5, 0x1

    .line 90
    invoke-direct {p4, p3, p5}, Lio/opentelemetry/sdk/metrics/internal/state/a;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;I)V

    .line 91
    .line 92
    .line 93
    invoke-direct {p2, p4}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;-><init>(Ljava/util/function/Supplier;)V

    .line 94
    .line 95
    .line 96
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusableHandlesPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 97
    .line 98
    new-instance p2, Lfx0/e;

    .line 99
    .line 100
    const/4 p3, 0x4

    .line 101
    invoke-direct {p2, p0, p3}, Lfx0/e;-><init>(Ljava/lang/Object;I)V

    .line 102
    .line 103
    .line 104
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->handleBuilder:Ljava/util/function/Function;

    .line 105
    .line 106
    new-instance p2, Lio/opentelemetry/sdk/metrics/internal/state/b;

    .line 107
    .line 108
    const/4 p3, 0x0

    .line 109
    invoke-direct {p2, p0, p3}, Lio/opentelemetry/sdk/metrics/internal/state/b;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;I)V

    .line 110
    .line 111
    .line 112
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->handleReleaser:Ljava/util/function/BiConsumer;

    .line 113
    .line 114
    new-instance p2, Lio/opentelemetry/sdk/metrics/internal/state/b;

    .line 115
    .line 116
    const/4 p3, 0x1

    .line 117
    invoke-direct {p2, p0, p3}, Lio/opentelemetry/sdk/metrics/internal/state/b;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;I)V

    .line 118
    .line 119
    .line 120
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->pointReleaser:Ljava/util/function/BiConsumer;

    .line 121
    .line 122
    sget-object p2, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 123
    .line 124
    if-ne p1, p2, :cond_0

    .line 125
    .line 126
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;

    .line 127
    .line 128
    invoke-direct {p1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;-><init>()V

    .line 129
    .line 130
    .line 131
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 132
    .line 133
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;

    .line 134
    .line 135
    invoke-direct {p1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;-><init>()V

    .line 136
    .line 137
    .line 138
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 139
    .line 140
    return-void

    .line 141
    :cond_0
    new-instance p1, Ljava/util/HashMap;

    .line 142
    .line 143
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 144
    .line 145
    .line 146
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 147
    .line 148
    new-instance p1, Ljava/util/HashMap;

    .line 149
    .line 150
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 151
    .line 152
    .line 153
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 154
    .line 155
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/Map;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lambda$collectWithDeltaAggregationTemporality$3(Ljava/util/Map;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lambda$new$2(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lambda$collectWithCumulativeAggregationTemporality$5(Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private collectWithCumulativeAggregationTemporality()Ljava/util/Collection;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsList:Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsList:Ljava/util/List;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    :goto_0
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 21
    .line 22
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/state/c;

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-direct {v2, p0, v0, v3}, Lio/opentelemetry/sdk/metrics/internal/state/c;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;I)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v1, v2}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 29
    .line 30
    .line 31
    return-object v0
.end method

.method private collectWithDeltaAggregationTemporality()Ljava/util/Collection;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsList:Ljava/util/List;

    .line 8
    .line 9
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 10
    .line 11
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    new-instance v3, Lex0/a;

    .line 15
    .line 16
    const/4 v4, 0x3

    .line 17
    invoke-direct {v3, v2, v4}, Lex0/a;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v0, v3}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsList:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsMap:Ljava/util/Map;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v0, Ljava/util/HashMap;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 37
    .line 38
    new-instance v3, Lio/opentelemetry/api/baggage/a;

    .line 39
    .line 40
    const/4 v4, 0x2

    .line 41
    invoke-direct {v3, v4, p0, v0}, Lio/opentelemetry/api/baggage/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {v2, v3}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 45
    .line 46
    .line 47
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 48
    .line 49
    if-ne v2, v1, :cond_1

    .line 50
    .line 51
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsList:Ljava/util/List;

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    new-instance v2, Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 57
    .line 58
    .line 59
    :goto_1
    new-instance v3, Lio/opentelemetry/sdk/metrics/internal/state/c;

    .line 60
    .line 61
    const/4 v4, 0x0

    .line 62
    invoke-direct {v3, p0, v2, v4}, Lio/opentelemetry/sdk/metrics/internal/state/c;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;I)V

    .line 63
    .line 64
    .line 65
    invoke-interface {v0, v3}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 66
    .line 67
    .line 68
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 69
    .line 70
    if-ne v3, v1, :cond_2

    .line 71
    .line 72
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 73
    .line 74
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->pointReleaser:Ljava/util/function/BiConsumer;

    .line 75
    .line 76
    invoke-interface {v0, v1}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 77
    .line 78
    .line 79
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 80
    .line 81
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 82
    .line 83
    .line 84
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 85
    .line 86
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsMap:Ljava/util/Map;

    .line 87
    .line 88
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 89
    .line 90
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsMap:Ljava/util/Map;

    .line 91
    .line 92
    return-object v2

    .line 93
    :cond_2
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 94
    .line 95
    return-object v2
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Z)Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T::",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">(",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Z)",
            "Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage<",
            "TT;>;"
        }
    .end annotation

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v0, v1, p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->create(Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 18
    .line 19
    invoke-static {}, Lio/opentelemetry/sdk/metrics/ExemplarFilter;->alwaysOff()Lio/opentelemetry/sdk/metrics/ExemplarFilter;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-static {v1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;->asExemplarFilterInternal(Lio/opentelemetry/sdk/metrics/ExemplarFilter;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-interface {v2}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-interface {v0, p2, v1, v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;->createAggregator(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 40
    .line 41
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getCardinalityLimit()I

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    move-object v3, p0

    .line 50
    move v8, p3

    .line 51
    invoke-direct/range {v2 .. v8}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;-><init>(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;IZ)V

    .line 52
    .line 53
    .line 54
    return-object v2
.end method

.method public static synthetic d(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lambda$collectWithDeltaAggregationTemporality$4(Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic e(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lambda$new$0(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lambda$new$1(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$collectWithCumulativeAggregationTemporality$5(Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 7

    .line 1
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->startEpochNanos:J

    .line 2
    .line 3
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->epochNanos:J

    .line 4
    .line 5
    const/4 v6, 0x1

    .line 6
    move-object v5, p2

    .line 7
    move-object v0, p3

    .line 8
    invoke-virtual/range {v0 .. v6}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->aggregateThenMaybeReset(JJLio/opentelemetry/api/common/Attributes;Z)Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method private synthetic lambda$collectWithDeltaAggregationTemporality$3(Ljava/util/Map;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 7

    .line 1
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->startEpochNanos:J

    .line 2
    .line 3
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->epochNanos:J

    .line 4
    .line 5
    const/4 v6, 0x1

    .line 6
    move-object v5, p2

    .line 7
    move-object v0, p3

    .line 8
    invoke-virtual/range {v0 .. v6}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->aggregateThenMaybeReset(JJLio/opentelemetry/api/common/Attributes;Z)Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 13
    .line 14
    sget-object v0, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 15
    .line 16
    if-ne p3, v0, :cond_0

    .line 17
    .line 18
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 19
    .line 20
    invoke-virtual {p3}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->borrowObject()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p3

    .line 24
    check-cast p3, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 27
    .line 28
    invoke-interface {p0, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->copyPoint(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 29
    .line 30
    .line 31
    move-object p2, p3

    .line 32
    :cond_0
    invoke-interface {p1, v5, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method private synthetic lambda$collectWithDeltaAggregationTemporality$4(Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->lastPoints:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0, p2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 8
    .line 9
    if-nez p2, :cond_0

    .line 10
    .line 11
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 12
    .line 13
    sget-object v0, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 14
    .line 15
    if-ne p2, v0, :cond_2

    .line 16
    .line 17
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 18
    .line 19
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->borrowObject()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 24
    .line 25
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 26
    .line 27
    invoke-interface {p0, p3, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->copyPoint(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    move-object p3, p2

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 33
    .line 34
    sget-object v1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 35
    .line 36
    if-ne v0, v1, :cond_1

    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 39
    .line 40
    invoke-interface {p0, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->diffInPlace(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 45
    .line 46
    invoke-interface {p0, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->diff(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 47
    .line 48
    .line 49
    move-result-object p3

    .line 50
    :cond_2
    :goto_1
    invoke-interface {p1, p3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method private synthetic lambda$new$0(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusableHandlesPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->borrowObject()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 8
    .line 9
    return-object p0
.end method

.method private synthetic lambda$new$1(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusableHandlesPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->returnObject(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private synthetic lambda$new$2(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->reusablePointsPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->returnObject(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private validateAndProcessAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->maxCardinality:I

    .line 8
    .line 9
    if-lt v0, v1, :cond_0

    .line 10
    .line 11
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 14
    .line 15
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v2, "Instrument "

    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 23
    .line 24
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v2, " has exceeded the maximum allowed cardinality ("

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->maxCardinality:I

    .line 41
    .line 42
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string p0, ")."

    .line 46
    .line 47
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    sget-object p0, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;->CARDINALITY_OVERFLOW:Lio/opentelemetry/api/common/Attributes;

    .line 58
    .line 59
    return-object p0

    .line 60
    :cond_0
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 65
    .line 66
    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->process(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/common/Attributes;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method


# virtual methods
.method public collect(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJ)Lio/opentelemetry/sdk/metrics/data/MetricData;
    .locals 6

    .line 1
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 2
    .line 3
    sget-object p4, Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;->DELTA:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 4
    .line 5
    if-ne p3, p4, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->collectWithDeltaAggregationTemporality()Ljava/util/Collection;

    .line 8
    .line 9
    .line 10
    move-result-object p3

    .line 11
    :goto_0
    move-object v4, p3

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->collectWithCumulativeAggregationTemporality()Ljava/util/Collection;

    .line 14
    .line 15
    .line 16
    move-result-object p3

    .line 17
    goto :goto_0

    .line 18
    :goto_1
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 19
    .line 20
    iget-object p4, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->handleReleaser:Ljava/util/function/BiConsumer;

    .line 21
    .line 22
    invoke-interface {p3, p4}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 23
    .line 24
    .line 25
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    .line 26
    .line 27
    invoke-interface {p3}, Ljava/util/Map;->clear()V

    .line 28
    .line 29
    .line 30
    iget-boolean p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->enabled:Z

    .line 31
    .line 32
    if-eqz p3, :cond_1

    .line 33
    .line 34
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 35
    .line 36
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 37
    .line 38
    iget-object v5, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 39
    .line 40
    move-object v1, p1

    .line 41
    move-object v2, p2

    .line 42
    invoke-interface/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->toMetricData(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Ljava/util/Collection;Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :cond_1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/aggregator/EmptyMetricData;->getInstance()Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method

.method public getMetricDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRegisteredReader()Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 2
    .line 3
    return-object p0
.end method

.method public record(Lio/opentelemetry/api/common/Attributes;D)V
    .locals 1

    .line 4
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->validateAndProcessAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p1

    .line 5
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->handleBuilder:Ljava/util/function/Function;

    invoke-interface {v0, p1, p0}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 6
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    move-result-object v0

    invoke-virtual {p0, p2, p3, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->recordDouble(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    return-void
.end method

.method public record(Lio/opentelemetry/api/common/Attributes;J)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->validateAndProcessAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p1

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregatorHandles:Ljava/util/Map;

    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->handleBuilder:Ljava/util/function/Function;

    invoke-interface {v0, p1, p0}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 3
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    move-result-object v0

    invoke-virtual {p0, p2, p3, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->recordLong(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    return-void
.end method

.method public setEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->enabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public setEpochInformation(JJ)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;->DELTA:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 8
    .line 9
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getLastCollectEpochNanos()J

    .line 10
    .line 11
    .line 12
    move-result-wide p1

    .line 13
    :cond_0
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->startEpochNanos:J

    .line 14
    .line 15
    iput-wide p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->epochNanos:J

    .line 16
    .line 17
    return-void
.end method
