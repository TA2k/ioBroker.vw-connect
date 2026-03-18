.class public final Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_ENDPOINT:Ljava/lang/String; = "http://localhost:4318/v1/traces"

.field private static final DEFAULT_MEMORY_MODE:Lio/opentelemetry/sdk/common/export/MemoryMode;


# instance fields
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
    sget-object v0, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 2
    .line 3
    sput-object v0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->DEFAULT_MEMORY_MODE:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 5
    new-instance v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    const-string v2, "http://localhost:4318/v1/traces"

    invoke-direct {v0, v1, v2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;-><init>(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;Ljava/lang/String;)V

    sget-object v1, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->DEFAULT_MEMORY_MODE:Lio/opentelemetry/sdk/common/export/MemoryMode;

    invoke-direct {p0, v0, v1}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 4
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
    invoke-static {p0}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->lambda$setMeterProvider$0(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/api/metrics/MeterProvider;

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
.method public addHeader(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->addConstantHeaders(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporter;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporter;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->build()Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, p0}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporter;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public setClientTls([B[B)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setKeyManagerFromCerts([B[B)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "componentLoader"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "compressionMethod"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
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
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    invoke-virtual {v0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setConnectTimeout(Ljava/time/Duration;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 2

    .line 4
    const-string v0, "timeout"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "endpoint"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setExecutorService(Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "executorService"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setExecutorService(Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setHeaders(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;)",
            "Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setHeadersSupplier(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setInternalTelemetryVersion(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "schemaVersion"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setInternalTelemetryVersion(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setMemoryMode(Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "memoryMode"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 7
    .line 8
    return-object p0
.end method

.method public setMeterProvider(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 2

    .line 1
    const-string v0, "meterProvider"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    new-instance v0, Lio/opentelemetry/exporter/otlp/http/logs/b;

    const/4 v1, 0x2

    invoke-direct {v0, p1, v1}, Lio/opentelemetry/exporter/otlp/http/logs/b;-><init>(Lio/opentelemetry/api/metrics/MeterProvider;I)V

    invoke-virtual {p0, v0}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;

    return-object p0
.end method

.method public setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;)",
            "Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;"
        }
    .end annotation

    .line 3
    const-string v0, "meterProviderSupplier"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setProxy(Lio/opentelemetry/sdk/common/export/ProxyOptions;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    const-string v0, "proxyOptions"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setProxyOptions(Lio/opentelemetry/sdk/common/export/ProxyOptions;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1
    .param p1    # Lio/opentelemetry/sdk/common/export/RetryPolicy;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setServiceClassLoader(Ljava/lang/ClassLoader;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
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
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
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
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    invoke-virtual {v0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    return-object p0
.end method

.method public setTimeout(Ljava/time/Duration;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 2

    .line 4
    const-string v0, "timeout"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setTrustedCertificates([B)Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setTrustManagerFromCerts([B)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
