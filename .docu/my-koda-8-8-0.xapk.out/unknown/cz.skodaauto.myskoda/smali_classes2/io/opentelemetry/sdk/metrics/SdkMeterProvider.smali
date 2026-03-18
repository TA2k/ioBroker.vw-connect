.class public final Lio/opentelemetry/sdk/metrics/SdkMeterProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/MeterProvider;
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/SdkMeterProvider$LeasedMetricProducer;,
        Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;
    }
.end annotation


# static fields
.field static final DEFAULT_METER_NAME:Ljava/lang/String; = "unknown"

.field private static final LOGGER:Ljava/util/logging/Logger;


# instance fields
.field private final isClosed:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private meterConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ">;"
        }
    .end annotation
.end field

.field private final metricProducers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/export/MetricProducer;",
            ">;"
        }
    .end annotation
.end field

.field private final registeredReaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            ">;"
        }
    .end annotation
.end field

.field private final registeredViews:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;"
        }
    .end annotation
.end field

.field private final registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/metrics/SdkMeter;",
            ">;"
        }
    .end annotation
.end field

.field private final sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

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
    sput-object v0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/util/IdentityHashMap;Ljava/util/List;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;",
            "Ljava/util/IdentityHashMap<",
            "Lio/opentelemetry/sdk/metrics/export/MetricReader;",
            "Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;",
            ">;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/export/MetricProducer;",
            ">;",
            "Lio/opentelemetry/sdk/common/Clock;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->isClosed:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    invoke-interface {p4}, Lio/opentelemetry/sdk/common/Clock;->now()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredViews:Ljava/util/List;

    .line 17
    .line 18
    invoke-virtual {p2}, Ljava/util/IdentityHashMap;->entrySet()Ljava/util/Set;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    invoke-interface {p2}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    new-instance v2, Lio/opentelemetry/sdk/metrics/f;

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    invoke-direct {v2, p1, v3}, Lio/opentelemetry/sdk/metrics/f;-><init>(Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p2, v2}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-static {}, Ljava/util/stream/Collectors;->toList()Ljava/util/stream/Collector;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    invoke-interface {p1, p2}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    check-cast p1, Ljava/util/List;

    .line 45
    .line 46
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 47
    .line 48
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->metricProducers:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {p4, p5, p6, v0, v1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->create(Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;J)Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 55
    .line 56
    new-instance p2, Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 57
    .line 58
    new-instance p4, Lio/opentelemetry/sdk/metrics/f;

    .line 59
    .line 60
    const/4 p5, 0x1

    .line 61
    invoke-direct {p4, p0, p5}, Lio/opentelemetry/sdk/metrics/f;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    invoke-direct {p2, p4}, Lio/opentelemetry/sdk/internal/ComponentRegistry;-><init>(Ljava/util/function/Function;)V

    .line 65
    .line 66
    .line 67
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 68
    .line 69
    iput-object p7, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->meterConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 70
    .line 71
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_0

    .line 80
    .line 81
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 86
    .line 87
    new-instance p4, Ljava/util/ArrayList;

    .line 88
    .line 89
    invoke-direct {p4, p3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 90
    .line 91
    .line 92
    new-instance p5, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$LeasedMetricProducer;

    .line 93
    .line 94
    iget-object p6, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 95
    .line 96
    iget-object p7, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 97
    .line 98
    invoke-direct {p5, p6, p7, p2}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$LeasedMetricProducer;-><init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p4, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 105
    .line 106
    .line 107
    move-result-object p5

    .line 108
    new-instance p6, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;

    .line 109
    .line 110
    iget-object p7, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 111
    .line 112
    const/4 v2, 0x0

    .line 113
    invoke-direct {p6, p4, p7, v2}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;-><init>(Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;Lio/opentelemetry/sdk/metrics/SdkMeterProvider$1;)V

    .line 114
    .line 115
    .line 116
    invoke-interface {p5, p6}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->register(Lio/opentelemetry/sdk/metrics/export/CollectionRegistration;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p2, v0, v1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->setLastCollectEpochNanos(J)V

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_0
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;Lio/opentelemetry/sdk/metrics/SdkMeter;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->lambda$setMeterConfigurator$2(Lio/opentelemetry/sdk/metrics/SdkMeter;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Ljava/util/List;Ljava/util/Map$Entry;)Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->lambda$new$0(Ljava/util/List;Ljava/util/Map$Entry;)Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static builder()Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static synthetic d(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/SdkMeter;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->lambda$new$1(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private getMeterConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/internal/MeterConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->meterConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/MeterConfig;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/MeterConfig;->defaultConfig()Lio/opentelemetry/sdk/metrics/internal/MeterConfig;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :cond_0
    return-object p0
.end method

.method private static synthetic lambda$new$0(Ljava/util/List;Ljava/util/Map$Entry;)Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;
    .locals 2

    .line 1
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 6
    .line 7
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;

    .line 18
    .line 19
    invoke-static {v1, p1, p0}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->create(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->create(Lio/opentelemetry/sdk/metrics/export/MetricReader;Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;)Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method private synthetic lambda$new$1(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/SdkMeter;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->getMeterConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/internal/MeterConfig;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-direct {v0, v1, p1, v2, p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/MeterConfig;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method private synthetic lambda$setMeterConfigurator$2(Lio/opentelemetry/sdk/metrics/SdkMeter;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->getMeterConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/internal/MeterConfig;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->updateMeterConfig(Lio/opentelemetry/sdk/metrics/internal/MeterConfig;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-wide/16 v0, 0xa

    .line 6
    .line 7
    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1, v2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->join(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 36
    .line 37
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-static {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofAll(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method

.method public meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/MeterProvider;->meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    if-eqz p1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    :cond_1
    sget-object p1, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->LOGGER:Ljava/util/logging/Logger;

    .line 27
    .line 28
    const-string v0, "Meter requested without instrumentation scope name."

    .line 29
    .line 30
    invoke-virtual {p1, v0}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string p1, "unknown"

    .line 34
    .line 35
    :cond_2
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;

    .line 36
    .line 37
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 38
    .line 39
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;-><init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-object v0
.end method

.method public resetForTest()V
    .locals 2

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->getComponents()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v0, Lio/opentelemetry/sdk/metrics/e;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/e;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0, v0}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setMeterConfigurator(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->meterConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 2
    .line 3
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 4
    .line 5
    invoke-virtual {p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->getComponents()Ljava/util/Collection;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance v0, Lio/opentelemetry/sdk/metrics/d;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/metrics/d;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p1, v0}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->isClosed:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "Multiple close calls"

    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ljava/util/logging/Logger;->info(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_2

    .line 52
    .line 53
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    check-cast v1, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 58
    .line 59
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_2
    invoke-static {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofAll(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SdkMeterProvider{clock="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 9
    .line 10
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getClock()Lio/opentelemetry/sdk/common/Clock;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", resource="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 23
    .line 24
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", metricReaders="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredReaders:Ljava/util/List;

    .line 37
    .line 38
    invoke-interface {v1}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    new-instance v2, Lio/opentelemetry/sdk/metrics/c;

    .line 43
    .line 44
    const/4 v3, 0x2

    .line 45
    invoke-direct {v2, v3}, Lio/opentelemetry/sdk/metrics/c;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-interface {v1, v2}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-static {}, Ljava/util/stream/Collectors;->toList()Ljava/util/stream/Collector;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-interface {v1, v2}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", metricProducers="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->metricProducers:Ljava/util/List;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", views="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->registeredViews:Ljava/util/List;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", meterConfigurator="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->meterConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 89
    .line 90
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string p0, "}"

    .line 94
    .line 95
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method
