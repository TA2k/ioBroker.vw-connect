.class public final Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_EXEMPLAR_FILTER:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;


# instance fields
.field private clock:Lio/opentelemetry/sdk/common/Clock;

.field private exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

.field private meterConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
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

.field private final metricReaders:Ljava/util/IdentityHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/IdentityHashMap<",
            "Lio/opentelemetry/sdk/metrics/export/MetricReader;",
            "Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;",
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

.field private resource:Lio/opentelemetry/sdk/resources/Resource;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/ExemplarFilter;->traceBased()Lio/opentelemetry/sdk/metrics/ExemplarFilter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;->asExemplarFilterInternal(Lio/opentelemetry/sdk/metrics/ExemplarFilter;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->DEFAULT_EXEMPLAR_FILTER:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 9
    .line 10
    invoke-static {}, Lio/opentelemetry/sdk/resources/Resource;->getDefault()Lio/opentelemetry/sdk/resources/Resource;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 15
    .line 16
    new-instance v0, Ljava/util/IdentityHashMap;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/util/IdentityHashMap;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricReaders:Ljava/util/IdentityHashMap;

    .line 22
    .line 23
    new-instance v0, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricProducers:Ljava/util/List;

    .line 29
    .line 30
    new-instance v0, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->registeredViews:Ljava/util/List;

    .line 36
    .line 37
    sget-object v0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->DEFAULT_EXEMPLAR_FILTER:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 38
    .line 39
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 40
    .line 41
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/MeterConfig;->configuratorBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->meterConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public addMeterConfiguratorCondition(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/metrics/internal/MeterConfig;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ")",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->meterConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->addCondition(Ljava/util/function/Predicate;Ljava/lang/Object;)Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public addResource(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "resource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/resources/Resource;->merge(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/resources/Resource;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 13
    .line 14
    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/metrics/SdkMeterProvider;
    .locals 8

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->registeredViews:Ljava/util/List;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricReaders:Ljava/util/IdentityHashMap;

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricProducers:Ljava/util/List;

    .line 8
    .line 9
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 10
    .line 11
    iget-object v5, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 12
    .line 13
    iget-object v6, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 14
    .line 15
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->meterConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 16
    .line 17
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->build()Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 18
    .line 19
    .line 20
    move-result-object v7

    .line 21
    invoke-direct/range {v0 .. v7}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;-><init>(Ljava/util/List;Ljava/util/IdentityHashMap;Ljava/util/List;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public registerMetricProducer(Lio/opentelemetry/sdk/metrics/export/MetricProducer;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricProducers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public registerMetricReader(Lio/opentelemetry/sdk/metrics/export/MetricReader;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricReaders:Ljava/util/IdentityHashMap;

    invoke-static {}, Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;->defaultCardinalityLimitSelector()Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;

    move-result-object v1

    invoke-virtual {v0, p1, v1}, Ljava/util/IdentityHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p0
.end method

.method public registerMetricReader(Lio/opentelemetry/sdk/metrics/export/MetricReader;Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->metricReaders:Ljava/util/IdentityHashMap;

    invoke-virtual {v0, p1, p2}, Ljava/util/IdentityHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p0
.end method

.method public registerView(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/View;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 4

    .line 1
    const-string v0, "selector"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    const-string v0, "view"

    .line 7
    .line 8
    invoke-static {p2, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->registeredViews:Ljava/util/List;

    .line 12
    .line 13
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/View;->getAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/View;->getCardinalityLimit()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;->fromCurrentStack()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-static {p1, p2, v1, v2, v3}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->create(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;ILio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;)Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    return-object p0
.end method

.method public setClock(Lio/opentelemetry/sdk/common/Clock;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "clock"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 7
    .line 8
    return-object p0
.end method

.method public setExemplarFilter(Lio/opentelemetry/sdk/metrics/ExemplarFilter;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 0

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;->asExemplarFilterInternal(Lio/opentelemetry/sdk/metrics/ExemplarFilter;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 6
    .line 7
    return-object p0
.end method

.method public setMeterConfigurator(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/sdk/internal/ScopeConfigurator;->toBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->meterConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 6
    .line 7
    return-object p0
.end method

.method public setResource(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "resource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    return-object p0
.end method
