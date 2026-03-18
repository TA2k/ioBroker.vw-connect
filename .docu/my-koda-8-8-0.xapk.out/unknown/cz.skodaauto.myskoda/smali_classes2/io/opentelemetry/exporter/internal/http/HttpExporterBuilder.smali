.class public final Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# static fields
.field public static final DEFAULT_CONNECT_TIMEOUT_SECS:J = 0xaL

.field public static final DEFAULT_TIMEOUT_SECS:J = 0xaL

.field private static final LOGGER:Ljava/util/logging/Logger;


# instance fields
.field private componentLoader:Lio/opentelemetry/common/ComponentLoader;

.field private compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private connectTimeoutNanos:J

.field private final constantHeaders:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private endpoint:Ljava/lang/String;

.field private executorService:Ljava/util/concurrent/ExecutorService;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private exportAsJson:Z

.field private exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field private headerSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field private internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

.field private meterProviderSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;"
        }
    .end annotation
.end field

.field private proxyOptions:Lio/opentelemetry/sdk/common/export/ProxyOptions;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private timeoutNanos:J

.field private tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

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
    sput-object v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;Ljava/lang/String;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 5
    .line 6
    const-wide/16 v1, 0xa

    .line 7
    .line 8
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v3

    .line 12
    iput-wide v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->timeoutNanos:J

    .line 13
    .line 14
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    iput-wide v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->connectTimeoutNanos:J

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput-boolean v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson:Z

    .line 22
    .line 23
    new-instance v0, Ljava/util/HashMap;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->constantHeaders:Ljava/util/Map;

    .line 29
    .line 30
    new-instance v0, Lio/opentelemetry/exporter/internal/grpc/b;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/grpc/b;-><init>(I)V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->headerSupplier:Ljava/util/function/Supplier;

    .line 37
    .line 38
    new-instance v0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 39
    .line 40
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 44
    .line 45
    invoke-static {}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getDefault()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 50
    .line 51
    new-instance v0, Lio/opentelemetry/exporter/internal/grpc/b;

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/grpc/b;-><init>(I)V

    .line 55
    .line 56
    .line 57
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 58
    .line 59
    sget-object v0, Lio/opentelemetry/sdk/common/InternalTelemetryVersion;->LEGACY:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    .line 60
    .line 61
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    .line 62
    .line 63
    const-class v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-static {v0}, Lio/opentelemetry/common/ComponentLoader;->forClassLoader(Ljava/lang/ClassLoader;)Lio/opentelemetry/common/ComponentLoader;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    .line 74
    .line 75
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 76
    .line 77
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 78
    .line 79
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->lambda$build$3()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->lambda$build$2(Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->lambda$toString$4(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic d(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->lambda$build$0(Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic e(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->lambda$toString$5(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic f(Ljava/util/List;Ljava/util/List;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->lambda$build$1(Ljava/util/List;Ljava/util/List;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$build$0(Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p2}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private static synthetic lambda$build$1(Ljava/util/List;Ljava/util/List;)Ljava/util/List;
    .locals 1

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method private static synthetic lambda$build$2(Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-static {p2}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    new-instance v0, Lio/opentelemetry/exporter/internal/grpc/d;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/grpc/d;-><init>(I)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0, p1, p2, v0}, Ljava/util/Map;->merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method private synthetic lambda$build$3()Ljava/util/Map;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->headerSupplier:Ljava/util/function/Supplier;

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Ljava/util/Map;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    new-instance v2, Lio/opentelemetry/exporter/internal/grpc/e;

    .line 17
    .line 18
    const/4 v3, 0x2

    .line 19
    invoke-direct {v2, v0, v3}, Lio/opentelemetry/exporter/internal/grpc/e;-><init>(Ljava/util/HashMap;I)V

    .line 20
    .line 21
    .line 22
    invoke-interface {v1, v2}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->constantHeaders:Ljava/util/Map;

    .line 26
    .line 27
    new-instance v1, Lio/opentelemetry/exporter/internal/grpc/e;

    .line 28
    .line 29
    const/4 v2, 0x3

    .line 30
    invoke-direct {v1, v0, v2}, Lio/opentelemetry/exporter/internal/grpc/e;-><init>(Ljava/util/HashMap;I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p0, v1}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 34
    .line 35
    .line 36
    return-object v0
.end method

.method private static synthetic lambda$toString$4(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    new-instance p2, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    const-string p1, "=OBFUSCATED"

    .line 10
    .line 11
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method private static synthetic lambda$toString$5(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    new-instance p2, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    const-string p1, "=OBFUSCATED"

    .line 10
    .line 11
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method private static mapToJsonTypeIfPossible(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_2

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq v0, v1, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    sget-object p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_2
    sget-object p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 26
    .line 27
    return-object p0
.end method

.method private resolveHttpSenderProvider()Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    .line 7
    .line 8
    const-class v1, Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;

    .line 9
    .line 10
    invoke-interface {p0, v1}, Lio/opentelemetry/common/ComponentLoader;->load(Ljava/lang/Class;)Ljava/lang/Iterable;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {v0}, Ljava/util/HashMap;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-nez p0, :cond_4

    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/util/HashMap;->size()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    const/4 v1, 0x1

    .line 53
    if-ne p0, v1, :cond_1

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-interface {p0}, Ljava/util/stream/Stream;->findFirst()Ljava/util/Optional;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p0}, Ljava/util/Optional;->get()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;

    .line 72
    .line 73
    return-object p0

    .line 74
    :cond_1
    const-string p0, "io.opentelemetry.exporter.internal.http.HttpSenderProvider"

    .line 75
    .line 76
    const-string v1, ""

    .line 77
    .line 78
    invoke-static {p0, v1}, Lio/opentelemetry/api/internal/ConfigUtil;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-eqz v1, :cond_2

    .line 87
    .line 88
    sget-object p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->LOGGER:Ljava/util/logging/Logger;

    .line 89
    .line 90
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 91
    .line 92
    const-string v2, "Multiple HttpSenderProvider found. Please include only one, or specify preference setting io.opentelemetry.exporter.internal.http.HttpSenderProvider to the FQCN of the preferred provider."

    .line 93
    .line 94
    invoke-virtual {p0, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-interface {p0}, Ljava/util/stream/Stream;->findFirst()Ljava/util/Optional;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-virtual {p0}, Ljava/util/Optional;->get()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;

    .line 114
    .line 115
    return-object p0

    .line 116
    :cond_2
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-eqz v1, :cond_3

    .line 121
    .line 122
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;

    .line 127
    .line 128
    return-object p0

    .line 129
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    const-string v1, "No HttpSenderProvider matched configured io.opentelemetry.exporter.internal.http.HttpSenderProvider: "

    .line 132
    .line 133
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw v0

    .line 141
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 142
    .line 143
    const-string v0, "No HttpSenderProvider found on classpath. Please add dependency on opentelemetry-exporter-sender-okhttp or opentelemetry-exporter-sender-jdk"

    .line 144
    .line 145
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0
.end method


# virtual methods
.method public addConstantHeaders(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->constantHeaders:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/exporter/internal/http/HttpExporter;
    .locals 15
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/exporter/internal/http/HttpExporter<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v8, Lex0/n;

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    invoke-direct {v8, p0, v0}, Lex0/n;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 8
    .line 9
    const-string v1, "http://"

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->resolveHttpSenderProvider()Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;

    .line 16
    .line 17
    .line 18
    move-result-object v14

    .line 19
    move v1, v0

    .line 20
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 21
    .line 22
    move v2, v1

    .line 23
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 24
    .line 25
    move v3, v2

    .line 26
    iget-boolean v2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson:Z

    .line 27
    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    const-string v4, "application/json"

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const-string v4, "application/x-protobuf"

    .line 34
    .line 35
    :goto_0
    iget-wide v5, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->timeoutNanos:J

    .line 36
    .line 37
    move v9, v3

    .line 38
    move-object v3, v4

    .line 39
    move-wide v4, v5

    .line 40
    iget-wide v6, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->connectTimeoutNanos:J

    .line 41
    .line 42
    move v10, v9

    .line 43
    iget-object v9, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->proxyOptions:Lio/opentelemetry/sdk/common/export/ProxyOptions;

    .line 44
    .line 45
    move v11, v10

    .line 46
    iget-object v10, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 47
    .line 48
    const/4 v12, 0x0

    .line 49
    if-eqz v11, :cond_1

    .line 50
    .line 51
    move-object v13, v12

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    iget-object v13, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 54
    .line 55
    invoke-virtual {v13}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->getSslContext()Ljavax/net/ssl/SSLContext;

    .line 56
    .line 57
    .line 58
    move-result-object v13

    .line 59
    :goto_1
    if-eqz v11, :cond_2

    .line 60
    .line 61
    :goto_2
    move-object v11, v13

    .line 62
    goto :goto_3

    .line 63
    :cond_2
    iget-object v11, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 64
    .line 65
    invoke-virtual {v11}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->getTrustManager()Ljavax/net/ssl/X509TrustManager;

    .line 66
    .line 67
    .line 68
    move-result-object v12

    .line 69
    goto :goto_2

    .line 70
    :goto_3
    iget-object v13, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 71
    .line 72
    invoke-static/range {v0 .. v13}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->create(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;ZLjava/lang/String;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/ProxyOptions;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-interface {v14, v0}, Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;->createSender(Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;)Lio/opentelemetry/exporter/internal/http/HttpSender;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    sget-object v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->LOGGER:Ljava/util/logging/Logger;

    .line 81
    .line 82
    sget-object v1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 83
    .line 84
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    const-string v4, "Using HttpSender: "

    .line 93
    .line 94
    invoke-virtual {v4, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    invoke-virtual {v0, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    new-instance v1, Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 102
    .line 103
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 104
    .line 105
    invoke-static {v0}, Lio/opentelemetry/sdk/internal/ComponentId;->generateLazy(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Lio/opentelemetry/sdk/internal/StandardComponentId;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    iget-object v4, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 110
    .line 111
    iget-object v5, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    .line 112
    .line 113
    iget-object v6, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 114
    .line 115
    invoke-direct/range {v1 .. v6}, Lio/opentelemetry/exporter/internal/http/HttpExporter;-><init>(Lio/opentelemetry/sdk/internal/StandardComponentId;Lio/opentelemetry/exporter/internal/http/HttpSender;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/common/InternalTelemetryVersion;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    return-object v1
.end method

.method public copy()Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;-><init>(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 13
    .line 14
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->timeoutNanos:J

    .line 15
    .line 16
    iput-wide v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->timeoutNanos:J

    .line 17
    .line 18
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->connectTimeoutNanos:J

    .line 19
    .line 20
    iput-wide v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->connectTimeoutNanos:J

    .line 21
    .line 22
    iget-boolean v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson:Z

    .line 23
    .line 24
    iput-boolean v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson:Z

    .line 25
    .line 26
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 27
    .line 28
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 29
    .line 30
    iget-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->constantHeaders:Ljava/util/Map;

    .line 31
    .line 32
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->constantHeaders:Ljava/util/Map;

    .line 33
    .line 34
    invoke-interface {v1, v2}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->headerSupplier:Ljava/util/function/Supplier;

    .line 38
    .line 39
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->headerSupplier:Ljava/util/function/Supplier;

    .line 40
    .line 41
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 42
    .line 43
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->copy()Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 48
    .line 49
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 50
    .line 51
    if-eqz v1, :cond_0

    .line 52
    .line 53
    invoke-virtual {v1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->toBuilder()Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {v1}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;->build()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 62
    .line 63
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 64
    .line 65
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 66
    .line 67
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    .line 68
    .line 69
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    .line 70
    .line 71
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->proxyOptions:Lio/opentelemetry/sdk/common/export/ProxyOptions;

    .line 72
    .line 73
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->proxyOptions:Lio/opentelemetry/sdk/common/export/ProxyOptions;

    .line 74
    .line 75
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    .line 76
    .line 77
    iput-object p0, v0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    .line 78
    .line 79
    return-object v0
.end method

.method public exportAsJson()Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson:Z

    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 5
    .line 6
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->mapToJsonTypeIfPossible(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 11
    .line 12
    return-object p0
.end method

.method public setComponentLoader(Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/common/ComponentLoader;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    .line 2
    .line 3
    return-object p0
.end method

.method public setCompression(Lio/opentelemetry/exporter/internal/compression/Compressor;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .param p1    # Lio/opentelemetry/exporter/internal/compression/Compressor;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/compression/Compressor;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    return-object p0
.end method

.method public setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    .line 3
    invoke-static {p1, v0}, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;->validateAndResolveCompressor(Ljava/lang/String;Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/internal/compression/Compressor;

    move-result-object p1

    .line 4
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->setCompression(Lio/opentelemetry/exporter/internal/compression/Compressor;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Ljava/util/concurrent/TimeUnit;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-wide p1, 0x7fffffffffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide p1

    .line 17
    :goto_0
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->connectTimeoutNanos:J

    .line 18
    .line 19
    return-object p0
.end method

.method public setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/ExporterBuilderUtil;->validateEndpoint(Ljava/lang/String;)Ljava/net/URI;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    .line 10
    .line 11
    return-object p0
.end method

.method public setExecutorService(Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/concurrent/ExecutorService;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    return-object p0
.end method

.method public setHeadersSupplier(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;)",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->headerSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    return-object p0
.end method

.method public setInternalTelemetryVersion(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InternalTelemetryVersion;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    .line 2
    .line 3
    return-object p0
.end method

.method public setKeyManagerFromCerts([B[B)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([B[B)",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->setKeyManagerFromCerts([B[B)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;)",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    return-object p0
.end method

.method public setProxyOptions(Lio/opentelemetry/sdk/common/export/ProxyOptions;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/export/ProxyOptions;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->proxyOptions:Lio/opentelemetry/sdk/common/export/ProxyOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 0
    .param p1    # Lio/opentelemetry/sdk/common/export/RetryPolicy;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 2
    .line 3
    return-object p0
.end method

.method public setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljavax/net/ssl/SSLContext;",
            "Ljavax/net/ssl/X509TrustManager;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Ljava/util/concurrent/TimeUnit;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-wide p1, 0x7fffffffffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide p1

    .line 17
    :goto_0
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->timeoutNanos:J

    .line 18
    .line 19
    return-object p0
.end method

.method public setTrustManagerFromCerts([B)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([B)",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->tlsConfigHelper:Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->setTrustManagerFromCerts([B)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    const/4 v0, 0x1

    .line 25
    invoke-virtual {p0, v0}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->toString(Z)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public toString(Z)Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "}"

    const-string v1, ", "

    if-eqz p1, :cond_0

    .line 2
    new-instance p1, Ljava/util/StringJoiner;

    const-string v2, "HttpExporterBuilder{"

    invoke-direct {p1, v1, v2, v0}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)V

    goto :goto_0

    .line 3
    :cond_0
    new-instance p1, Ljava/util/StringJoiner;

    invoke-direct {p1, v1}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;)V

    .line 4
    :goto_0
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "endpoint="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->endpoint:Ljava/lang/String;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 5
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "timeoutNanos="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->timeoutNanos:J

    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 6
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "proxyOptions="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->proxyOptions:Lio/opentelemetry/sdk/common/export/ProxyOptions;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "compressorEncoding="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 8
    invoke-static {v3}, Ljava/util/Optional;->ofNullable(Ljava/lang/Object;)Ljava/util/Optional;

    move-result-object v3

    new-instance v4, Lfx0/d;

    const/16 v5, 0x8

    invoke-direct {v4, v5}, Lfx0/d;-><init>(I)V

    invoke-virtual {v3, v4}, Ljava/util/Optional;->map(Ljava/util/function/Function;)Ljava/util/Optional;

    move-result-object v3

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Ljava/util/Optional;->orElse(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 9
    invoke-virtual {p1, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 10
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "connectTimeoutNanos="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->connectTimeoutNanos:J

    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 11
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "exportAsJson="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-boolean v3, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exportAsJson:Z

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 12
    new-instance v2, Ljava/util/StringJoiner;

    const-string v3, "Headers{"

    invoke-direct {v2, v1, v3, v0}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)V

    .line 13
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->constantHeaders:Ljava/util/Map;

    new-instance v1, Lio/opentelemetry/exporter/internal/grpc/c;

    const/4 v3, 0x2

    invoke-direct {v1, v2, v3}, Lio/opentelemetry/exporter/internal/grpc/c;-><init>(Ljava/util/StringJoiner;I)V

    invoke-interface {v0, v1}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 14
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->headerSupplier:Ljava/util/function/Supplier;

    invoke-interface {v0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map;

    if-eqz v0, :cond_1

    .line 15
    new-instance v1, Lio/opentelemetry/exporter/internal/grpc/c;

    const/4 v3, 0x3

    invoke-direct {v1, v2, v3}, Lio/opentelemetry/exporter/internal/grpc/c;-><init>(Ljava/util/StringJoiner;I)V

    invoke-interface {v0, v1}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 16
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "headers="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 17
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    if-eqz v0, :cond_2

    .line 18
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "retryPolicy="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 19
    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "componentLoader="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->componentLoader:Lio/opentelemetry/common/ComponentLoader;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 20
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->executorService:Ljava/util/concurrent/ExecutorService;

    if-eqz v0, :cond_3

    .line 21
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "executorService="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->executorService:Ljava/util/concurrent/ExecutorService;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 22
    :cond_3
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "exporterType="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->exporterType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 23
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "internalTelemetrySchemaVersion="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->internalTelemetryVersion:Lio/opentelemetry/sdk/common/InternalTelemetryVersion;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1, p0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 24
    invoke-virtual {p1}, Ljava/util/StringJoiner;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
