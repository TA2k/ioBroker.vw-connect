.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;


# static fields
.field private static final HTTP_SERVER_EXPERIMENTAL_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/api/common/Attributes;",
            ">;"
        }
    .end annotation
.end field

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final activeRequests:Lio/opentelemetry/api/metrics/LongUpDownCounter;

.field private final requestSize:Lio/opentelemetry/api/metrics/LongHistogram;

.field private final responseSize:Lio/opentelemetry/api/metrics/LongHistogram;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "http-server-experimental-metrics-start-attributes"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->HTTP_SERVER_EXPERIMENTAL_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;

    .line 8
    .line 9
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->logger:Ljava/util/logging/Logger;

    .line 20
    .line 21
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/api/metrics/Meter;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "http.server.active_requests"

    .line 5
    .line 6
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const-string v1, "{requests}"

    .line 11
    .line 12
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "Number of active HTTP server requests."

    .line 17
    .line 18
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->applyServerActiveRequestsAdvice(Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->activeRequests:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 30
    .line 31
    const-string v0, "http.server.request.body.size"

    .line 32
    .line 33
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const-string v1, "By"

    .line 38
    .line 39
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    const-string v2, "Size of HTTP server request bodies."

    .line 44
    .line 45
    invoke-interface {v0, v2}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->applyServerRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V

    .line 54
    .line 55
    .line 56
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->build()Lio/opentelemetry/api/metrics/LongHistogram;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->requestSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 61
    .line 62
    const-string v0, "http.server.response.body.size"

    .line 63
    .line 64
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-interface {p1, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    const-string v0, "Size of HTTP server response bodies."

    .line 73
    .line 74
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->applyServerRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V

    .line 83
    .line 84
    .line 85
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->build()Lio/opentelemetry/api/metrics/LongHistogram;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->responseSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 90
    .line 91
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;-><init>(Lio/opentelemetry/api/metrics/Meter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;
    .locals 2

    .line 1
    new-instance v0, Lfx0/d;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfx0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "experimental http server"

    .line 9
    .line 10
    invoke-static {v1, v0}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->create(Ljava/lang/String;Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    return-object v0
.end method


# virtual methods
.method public onEnd(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)V
    .locals 7

    .line 1
    sget-object p3, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->HTTP_SERVER_EXPERIMENTAL_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, p3}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p3

    .line 7
    check-cast p3, Lio/opentelemetry/api/common/Attributes;

    .line 8
    .line 9
    if-nez p3, :cond_0

    .line 10
    .line 11
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 14
    .line 15
    const-string p3, "No state present when ending context {0}. Cannot record HTTP request metrics."

    .line 16
    .line 17
    invoke-virtual {p0, p2, p3, p1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object p4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->activeRequests:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 22
    .line 23
    const-wide/16 v0, -0x1

    .line 24
    .line 25
    invoke-interface {p4, v0, v1, p3, p1}, Lio/opentelemetry/api/metrics/LongUpDownCounter;->add(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p3}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 29
    .line 30
    .line 31
    move-result-object p4

    .line 32
    invoke-interface {p4, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 33
    .line 34
    .line 35
    move-result-object p4

    .line 36
    invoke-interface {p4}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 37
    .line 38
    .line 39
    move-result-object p4

    .line 40
    const/4 v0, 0x2

    .line 41
    new-array v1, v0, [Lio/opentelemetry/api/common/Attributes;

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    aput-object p2, v1, v2

    .line 45
    .line 46
    const/4 v3, 0x1

    .line 47
    aput-object p3, v1, v3

    .line 48
    .line 49
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;->getHttpRequestBodySize([Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Long;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    if-eqz v1, :cond_1

    .line 54
    .line 55
    iget-object v4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->requestSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 58
    .line 59
    .line 60
    move-result-wide v5

    .line 61
    invoke-interface {v4, v5, v6, p4, p1}, Lio/opentelemetry/api/metrics/LongHistogram;->record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 62
    .line 63
    .line 64
    :cond_1
    new-array v0, v0, [Lio/opentelemetry/api/common/Attributes;

    .line 65
    .line 66
    aput-object p2, v0, v2

    .line 67
    .line 68
    aput-object p3, v0, v3

    .line 69
    .line 70
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;->getHttpResponseBodySize([Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Long;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-eqz p2, :cond_2

    .line 75
    .line 76
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->responseSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 77
    .line 78
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 79
    .line 80
    .line 81
    move-result-wide p2

    .line 82
    invoke-interface {p0, p2, p3, p4, p1}, Lio/opentelemetry/api/metrics/LongHistogram;->record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 83
    .line 84
    .line 85
    :cond_2
    return-void
.end method

.method public onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->activeRequests:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 2
    .line 3
    const-wide/16 p3, 0x1

    .line 4
    .line 5
    invoke-interface {p0, p3, p4, p2, p1}, Lio/opentelemetry/api/metrics/LongUpDownCounter;->add(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->HTTP_SERVER_EXPERIMENTAL_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;

    .line 9
    .line 10
    invoke-interface {p1, p0, p2}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
