.class public final Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_AGGREGATION_TEMPORALITY_SELECTOR:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

.field private static final DEFAULT_ENDPOINT:Ljava/lang/String; = "http://localhost:4318/v1/metrics"

.field private static final DEFAULT_MEMORY_MODE:Lio/opentelemetry/sdk/common/export/MemoryMode;


# instance fields
.field private aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

.field private defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

.field private final delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field private memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;->alwaysCumulative()Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->DEFAULT_AGGREGATION_TEMPORALITY_SELECTOR:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 6
    .line 7
    sget-object v0, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->DEFAULT_MEMORY_MODE:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 7
    new-instance v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    const-string v2, "http://localhost:4318/v1/metrics"

    invoke-direct {v0, v1, v2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;-><init>(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;Ljava/lang/String;)V

    sget-object v1, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->DEFAULT_AGGREGATION_TEMPORALITY_SELECTOR:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 8
    invoke-static {}, Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;->getDefault()Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    move-result-object v2

    sget-object v3, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->DEFAULT_MEMORY_MODE:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 9
    invoke-direct {p0, v0, v1, v2, v3}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;",
            "Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 4
    iput-object p3, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 5
    iput-object p4, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 6
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance p0, Lio/opentelemetry/api/logs/a;

    const/4 p2, 0x4

    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/logs/a;-><init>(Ljava/lang/Object;I)V

    invoke-static {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpUserAgent;->addUserAgentHeader(Ljava/util/function/BiConsumer;)V

    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->lambda$setMeterProvider$0(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/api/metrics/MeterProvider;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$setMeterProvider$0(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 0

    .line 1
    return-object p0
.end method


# virtual methods
.method public addHeader(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->addConstantHeaders(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporter;
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporter;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->build()Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget-object v3, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 10
    .line 11
    iget-object v4, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 12
    .line 13
    iget-object v5, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 14
    .line 15
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporter;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public exportAsJson()Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson()Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setAggregationTemporalitySelector(Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "aggregationTemporalitySelector"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 7
    .line 8
    return-object p0
.end method

.method public setClientTls([B[B)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setKeyManagerFromCerts([B[B)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "componentLoader"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "compressionMethod"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 2

    .line 1
    const-string v0, "unit"

    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-ltz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    .line 2
    :goto_0
    const-string v1, "timeout must be non-negative"

    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 3
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    invoke-virtual {v0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setConnectTimeout(Ljava/time/Duration;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 2

    .line 4
    const-string v0, "timeout"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setDefaultAggregationSelector(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "defaultAggregationSelector"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 7
    .line 8
    return-object p0
.end method

.method public setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "endpoint"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setExecutorService(Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "executorService"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setExecutorService(Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setHeaders(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;)",
            "Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setHeadersSupplier(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setInternalTelemetryVersion(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "schemaVersion"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setInternalTelemetryVersion(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setMemoryMode(Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "memoryMode"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 7
    .line 8
    return-object p0
.end method

.method public setMeterProvider(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 3

    .line 1
    const-string v0, "meterProvider"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    new-instance v1, Lio/opentelemetry/exporter/otlp/http/logs/b;

    const/4 v2, 0x1

    invoke-direct {v1, p1, v2}, Lio/opentelemetry/exporter/otlp/http/logs/b;-><init>(Lio/opentelemetry/api/metrics/MeterProvider;I)V

    invoke-virtual {v0, v1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;)",
            "Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;"
        }
    .end annotation

    .line 3
    const-string v0, "meterProvider"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setProxyOptions(Lio/opentelemetry/sdk/common/export/ProxyOptions;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "proxyOptions"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setProxyOptions(Lio/opentelemetry/sdk/common/export/ProxyOptions;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1
    .param p1    # Lio/opentelemetry/sdk/common/export/RetryPolicy;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setServiceClassLoader(Ljava/lang/ClassLoader;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "serviceClassLoader"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lio/opentelemetry/common/ComponentLoader;->forClassLoader(Ljava/lang/ClassLoader;)Lio/opentelemetry/common/ComponentLoader;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 2

    .line 1
    const-string v0, "unit"

    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-ltz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    .line 2
    :goto_0
    const-string v1, "timeout must be non-negative"

    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 3
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    invoke-virtual {v0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setTimeout(Ljava/time/Duration;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 2

    .line 4
    const-string v0, "timeout"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setTrustedCertificates([B)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setTrustManagerFromCerts([B)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
