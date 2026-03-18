.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;


# static fields
.field private static final HTTP_CLIENT_REQUEST_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;
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
.field private final requestSize:Lio/opentelemetry/api/metrics/LongHistogram;

.field private final responseSize:Lio/opentelemetry/api/metrics/LongHistogram;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "http-client-experimental-metrics-start-attributes"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->HTTP_CLIENT_REQUEST_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;

    .line 8
    .line 9
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;

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
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->logger:Ljava/util/logging/Logger;

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
    const-string v0, "http.client.request.body.size"

    .line 5
    .line 6
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const-string v1, "By"

    .line 11
    .line 12
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v2, "Size of HTTP client request bodies."

    .line 17
    .line 18
    invoke-interface {v0, v2}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->applyClientRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V

    .line 27
    .line 28
    .line 29
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->build()Lio/opentelemetry/api/metrics/LongHistogram;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->requestSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 34
    .line 35
    const-string v0, "http.client.response.body.size"

    .line 36
    .line 37
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-interface {p1, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    const-string v0, "Size of HTTP client response bodies."

    .line 46
    .line 47
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->applyClientRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->build()Lio/opentelemetry/api/metrics/LongHistogram;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->responseSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 63
    .line 64
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;-><init>(Lio/opentelemetry/api/metrics/Meter;)V

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
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfx0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "experimental http client"

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
    sget-object p3, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->HTTP_CLIENT_REQUEST_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;

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
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->logger:Ljava/util/logging/Logger;

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
    invoke-interface {p3}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 22
    .line 23
    .line 24
    move-result-object p4

    .line 25
    invoke-interface {p4, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object p4

    .line 29
    invoke-interface {p4}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 30
    .line 31
    .line 32
    move-result-object p4

    .line 33
    const/4 v0, 0x2

    .line 34
    new-array v1, v0, [Lio/opentelemetry/api/common/Attributes;

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    aput-object p2, v1, v2

    .line 38
    .line 39
    const/4 v3, 0x1

    .line 40
    aput-object p3, v1, v3

    .line 41
    .line 42
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;->getHttpRequestBodySize([Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Long;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    iget-object v4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->requestSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 51
    .line 52
    .line 53
    move-result-wide v5

    .line 54
    invoke-interface {v4, v5, v6, p4, p1}, Lio/opentelemetry/api/metrics/LongHistogram;->record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    new-array v0, v0, [Lio/opentelemetry/api/common/Attributes;

    .line 58
    .line 59
    aput-object p2, v0, v2

    .line 60
    .line 61
    aput-object p3, v0, v3

    .line 62
    .line 63
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;->getHttpResponseBodySize([Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Long;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    if-eqz p2, :cond_2

    .line 68
    .line 69
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->responseSize:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 70
    .line 71
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 72
    .line 73
    .line 74
    move-result-wide p2

    .line 75
    invoke-interface {p0, p2, p3, p4, p1}, Lio/opentelemetry/api/metrics/LongHistogram;->record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    return-void
.end method

.method public onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->HTTP_CLIENT_REQUEST_METRICS_START_ATTRIBUTES:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, p0, p2}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
