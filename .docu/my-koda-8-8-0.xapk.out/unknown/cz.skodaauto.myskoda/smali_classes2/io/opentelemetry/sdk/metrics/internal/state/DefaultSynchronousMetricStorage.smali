.class public final Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T::",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;"
    }
.end annotation


# static fields
.field private static final internalLogger:Ljava/util/logging/Logger;


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

.field private final aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentLinkedQueue<",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private volatile aggregatorHolder:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder<",
            "TT;>;"
        }
    .end annotation
.end field

.field private final attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

.field private volatile enabled:Z

.field private final logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

.field private final maxCardinality:I

.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private final metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

.field private volatile previousCollectionAggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

.field private final reusableResultList:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "TT;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;

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
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->internalLogger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;IZ)V
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
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->internalLogger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$1;)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHolder:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 20
    .line 21
    new-instance v0, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->reusableResultList:Ljava/util/ArrayList;

    .line 27
    .line 28
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->previousCollectionAggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;

    .line 34
    .line 35
    new-instance v0, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 36
    .line 37
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 41
    .line 42
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 43
    .line 44
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 45
    .line 46
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    invoke-interface {v0, p2}, Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;->getAggregationTemporality(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 63
    .line 64
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 65
    .line 66
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 67
    .line 68
    add-int/lit8 p5, p5, -0x1

    .line 69
    .line 70
    iput p5, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->maxCardinality:I

    .line 71
    .line 72
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 81
    .line 82
    iput-boolean p6, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->enabled:Z

    .line 83
    .line 84
    return-void
.end method

.method public static synthetic a(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->lambda$collect$0(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;JJZLjava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p8}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->lambda$collect$1(JJZLjava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private getAggregatorHandle(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/context/Context;",
            ")",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;"
        }
    .end annotation

    .line 1
    const-string v0, "attributes"

    .line 2
    .line 3
    invoke-static {p2, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 7
    .line 8
    invoke-virtual {v0, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->process(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    invoke-virtual {p1, p2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p3

    .line 16
    check-cast p3, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 17
    .line 18
    if-eqz p3, :cond_0

    .line 19
    .line 20
    return-object p3

    .line 21
    :cond_0
    invoke-virtual {p1}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 22
    .line 23
    .line 24
    move-result p3

    .line 25
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->maxCardinality:I

    .line 26
    .line 27
    if-lt p3, v0, :cond_1

    .line 28
    .line 29
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 30
    .line 31
    sget-object p3, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 32
    .line 33
    new-instance v0, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    const-string v1, "Instrument "

    .line 36
    .line 37
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 41
    .line 42
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, " has exceeded the maximum allowed cardinality ("

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->maxCardinality:I

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ")."

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-virtual {p2, p3, v0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    sget-object p2, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;->CARDINALITY_OVERFLOW:Lio/opentelemetry/api/common/Attributes;

    .line 76
    .line 77
    invoke-virtual {p1, p2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p3

    .line 81
    check-cast p3, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 82
    .line 83
    if-eqz p3, :cond_1

    .line 84
    .line 85
    return-object p3

    .line 86
    :cond_1
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 87
    .line 88
    invoke-virtual {p3}, Ljava/util/concurrent/ConcurrentLinkedQueue;->poll()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p3

    .line 92
    check-cast p3, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 93
    .line 94
    if-nez p3, :cond_2

    .line 95
    .line 96
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 97
    .line 98
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->createHandle()Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 99
    .line 100
    .line 101
    move-result-object p3

    .line 102
    :cond_2
    invoke-virtual {p1, p2, p3}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 107
    .line 108
    if-eqz p0, :cond_3

    .line 109
    .line 110
    return-object p0

    .line 111
    :cond_3
    return-object p3
.end method

.method private getHolderForRecord()Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    :goto_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHolder:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$200(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/atomic/AtomicInteger;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x2

    .line 8
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    rem-int/2addr v1, v2

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$200(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/atomic/AtomicInteger;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v1, -0x2

    .line 21
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    .line 22
    .line 23
    .line 24
    goto :goto_0
.end method

.method private static synthetic lambda$collect$0(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 0

    .line 1
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->hasRecordedValues()Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method private synthetic lambda$collect$1(JJZLjava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V
    .locals 8

    .line 1
    invoke-virtual/range {p8 .. p8}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->hasRecordedValues()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move-wide v2, p1

    .line 9
    move-wide v4, p3

    .line 10
    move v7, p5

    .line 11
    move-object v6, p7

    .line 12
    move-object/from16 v1, p8

    .line 13
    .line 14
    invoke-virtual/range {v1 .. v7}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->aggregateThenMaybeReset(JJLio/opentelemetry/api/common/Attributes;Z)Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    if-eqz p5, :cond_1

    .line 19
    .line 20
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 21
    .line 22
    sget-object p3, Lio/opentelemetry/sdk/common/export/MemoryMode;->IMMUTABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 23
    .line 24
    if-ne p2, p3, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 27
    .line 28
    move-object/from16 v1, p8

    .line 29
    .line 30
    invoke-virtual {p0, v1}, Ljava/util/concurrent/ConcurrentLinkedQueue;->offer(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    :cond_1
    if-eqz p1, :cond_2

    .line 34
    .line 35
    invoke-interface {p6, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    :cond_2
    :goto_0
    return-void
.end method

.method private releaseHolderForRecord(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder<",
            "TT;>;)V"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$200(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 p1, -0x2

    .line 6
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public collect(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJ)Lio/opentelemetry/sdk/metrics/data/MetricData;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;->DELTA:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 6
    .line 7
    const/4 v8, 0x0

    .line 8
    const/4 v9, 0x1

    .line 9
    if-ne v0, v2, :cond_0

    .line 10
    .line 11
    move v6, v9

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v6, v8

    .line 14
    :goto_0
    if-ne v0, v2, :cond_1

    .line 15
    .line 16
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->registeredReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 17
    .line 18
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getLastCollectEpochNanos()J

    .line 19
    .line 20
    .line 21
    move-result-wide v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move-wide/from16 v2, p3

    .line 24
    .line 25
    :goto_1
    if-eqz v6, :cond_4

    .line 26
    .line 27
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHolder:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 28
    .line 29
    iget-object v4, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 30
    .line 31
    sget-object v5, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 32
    .line 33
    const/4 v7, 0x0

    .line 34
    if-ne v4, v5, :cond_2

    .line 35
    .line 36
    new-instance v4, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 37
    .line 38
    iget-object v5, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->previousCollectionAggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;

    .line 39
    .line 40
    invoke-direct {v4, v5, v7}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;-><init>(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$1;)V

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    new-instance v4, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 45
    .line 46
    invoke-direct {v4, v7}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$1;)V

    .line 47
    .line 48
    .line 49
    :goto_2
    iput-object v4, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHolder:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 50
    .line 51
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$200(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/atomic/AtomicInteger;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-virtual {v4, v9}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    :goto_3
    if-le v4, v9, :cond_3

    .line 60
    .line 61
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$200(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/atomic/AtomicInteger;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$100(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/ConcurrentHashMap;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    :goto_4
    move-object v10, v0

    .line 75
    goto :goto_5

    .line 76
    :cond_4
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHolder:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 77
    .line 78
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$100(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/ConcurrentHashMap;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    goto :goto_4

    .line 83
    :goto_5
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 84
    .line 85
    sget-object v4, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 86
    .line 87
    if-ne v0, v4, :cond_5

    .line 88
    .line 89
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->reusableResultList:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 92
    .line 93
    .line 94
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->reusableResultList:Ljava/util/ArrayList;

    .line 95
    .line 96
    :goto_6
    move-object v15, v0

    .line 97
    goto :goto_7

    .line 98
    :cond_5
    new-instance v0, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-virtual {v10}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 101
    .line 102
    .line 103
    move-result v5

    .line 104
    invoke-direct {v0, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 105
    .line 106
    .line 107
    goto :goto_6

    .line 108
    :goto_7
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 109
    .line 110
    if-ne v0, v4, :cond_6

    .line 111
    .line 112
    if-eqz v6, :cond_6

    .line 113
    .line 114
    invoke-virtual {v10}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    iget v4, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->maxCardinality:I

    .line 119
    .line 120
    if-lt v0, v4, :cond_6

    .line 121
    .line 122
    new-instance v0, Lio/opentelemetry/api/logs/a;

    .line 123
    .line 124
    const/4 v4, 0x7

    .line 125
    invoke-direct {v0, v10, v4}, Lio/opentelemetry/api/logs/a;-><init>(Ljava/lang/Object;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v10, v0}, Ljava/util/concurrent/ConcurrentHashMap;->forEach(Ljava/util/function/BiConsumer;)V

    .line 129
    .line 130
    .line 131
    :cond_6
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/e;

    .line 132
    .line 133
    move-wide/from16 v4, p5

    .line 134
    .line 135
    move-object v7, v15

    .line 136
    invoke-direct/range {v0 .. v7}, Lio/opentelemetry/sdk/metrics/internal/state/e;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;JJZLjava/util/ArrayList;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v10, v0}, Ljava/util/concurrent/ConcurrentHashMap;->forEach(Ljava/util/function/BiConsumer;)V

    .line 140
    .line 141
    .line 142
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 143
    .line 144
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->size()I

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    iget v2, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->maxCardinality:I

    .line 149
    .line 150
    add-int/2addr v2, v9

    .line 151
    sub-int/2addr v0, v2

    .line 152
    :goto_8
    if-ge v8, v0, :cond_7

    .line 153
    .line 154
    iget-object v2, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 155
    .line 156
    invoke-virtual {v2}, Ljava/util/concurrent/ConcurrentLinkedQueue;->poll()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    add-int/lit8 v8, v8, 0x1

    .line 160
    .line 161
    goto :goto_8

    .line 162
    :cond_7
    if-eqz v6, :cond_8

    .line 163
    .line 164
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 165
    .line 166
    sget-object v2, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 167
    .line 168
    if-ne v0, v2, :cond_8

    .line 169
    .line 170
    iput-object v10, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->previousCollectionAggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;

    .line 171
    .line 172
    :cond_8
    invoke-interface {v15}, Ljava/util/List;->isEmpty()Z

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    if-nez v0, :cond_a

    .line 177
    .line 178
    iget-boolean v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->enabled:Z

    .line 179
    .line 180
    if-nez v0, :cond_9

    .line 181
    .line 182
    goto :goto_9

    .line 183
    :cond_9
    iget-object v11, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregator:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 184
    .line 185
    iget-object v14, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 186
    .line 187
    iget-object v0, v1, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 188
    .line 189
    move-object/from16 v12, p1

    .line 190
    .line 191
    move-object/from16 v13, p2

    .line 192
    .line 193
    move-object/from16 v16, v0

    .line 194
    .line 195
    invoke-interface/range {v11 .. v16}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->toMetricData(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Ljava/util/Collection;Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    return-object v0

    .line 200
    :cond_a
    :goto_9
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/aggregator/EmptyMetricData;->getInstance()Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    return-object v0
.end method

.method public getAggregatorHandlePool()Ljava/util/Queue;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Queue<",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->aggregatorHandlePool:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMetricDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->enabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public recordDouble(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->enabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-static {p1, p2}, Ljava/lang/Double;->isNaN(D)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 13
    .line 14
    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 15
    .line 16
    new-instance p4, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v0, "Instrument "

    .line 19
    .line 20
    invoke-direct {p4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->metricDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string p0, " has recorded measurement Not-a-Number (NaN) value with attributes "

    .line 37
    .line 38
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {p4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p0, ". Dropping measurement."

    .line 45
    .line 46
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-virtual {p1, p2, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->getHolderForRecord()Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    :try_start_0
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$100(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/ConcurrentHashMap;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-direct {p0, v1, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->getAggregatorHandle(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-virtual {v1, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->recordDouble(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 70
    .line 71
    .line 72
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->releaseHolderForRecord(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :catchall_0
    move-exception p1

    .line 77
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->releaseHolderForRecord(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)V

    .line 78
    .line 79
    .line 80
    throw p1
.end method

.method public recordLong(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->enabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->getHolderForRecord()Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    :try_start_0
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->access$100(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/ConcurrentHashMap;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-direct {p0, v1, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->getAggregatorHandle(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v1, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;->recordLong(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->releaseHolderForRecord(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->releaseHolderForRecord(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public setEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->enabled:Z

    .line 2
    .line 3
    return-void
.end method
