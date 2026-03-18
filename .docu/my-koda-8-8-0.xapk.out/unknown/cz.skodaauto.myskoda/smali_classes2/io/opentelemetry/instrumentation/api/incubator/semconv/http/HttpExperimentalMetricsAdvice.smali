.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final URL_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "url.template"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->URL_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static applyClientRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 7
    .line 8
    const/16 v0, 0x8

    .line 9
    .line 10
    new-array v0, v0, [Lio/opentelemetry/api/common/AttributeKey;

    .line 11
    .line 12
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    aput-object v1, v0, v2

    .line 16
    .line 17
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    aput-object v1, v0, v2

    .line 21
    .line 22
    sget-object v1, Lio/opentelemetry/semconv/ErrorAttributes;->ERROR_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 23
    .line 24
    const/4 v2, 0x2

    .line 25
    aput-object v1, v0, v2

    .line 26
    .line 27
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    const/4 v2, 0x3

    .line 30
    aput-object v1, v0, v2

    .line 31
    .line 32
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_VERSION:Lio/opentelemetry/api/common/AttributeKey;

    .line 33
    .line 34
    const/4 v2, 0x4

    .line 35
    aput-object v1, v0, v2

    .line 36
    .line 37
    sget-object v1, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 38
    .line 39
    const/4 v2, 0x5

    .line 40
    aput-object v1, v0, v2

    .line 41
    .line 42
    sget-object v1, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 43
    .line 44
    const/4 v2, 0x6

    .line 45
    aput-object v1, v0, v2

    .line 46
    .line 47
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalMetricsAdvice;->URL_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 48
    .line 49
    const/4 v2, 0x7

    .line 50
    aput-object v1, v0, v2

    .line 51
    .line 52
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method public static applyServerActiveRequestsAdvice(Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongUpDownCounterBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongUpDownCounterBuilder;

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    new-array v0, v0, [Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    aput-object v1, v0, v2

    .line 15
    .line 16
    sget-object v1, Lio/opentelemetry/semconv/UrlAttributes;->URL_SCHEME:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    aput-object v1, v0, v2

    .line 20
    .line 21
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedLongUpDownCounterBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedLongUpDownCounterBuilder;

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public static applyServerRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 7
    .line 8
    const/4 v0, 0x7

    .line 9
    new-array v0, v0, [Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_ROUTE:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    aput-object v1, v0, v2

    .line 15
    .line 16
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    aput-object v1, v0, v2

    .line 20
    .line 21
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    aput-object v1, v0, v2

    .line 25
    .line 26
    sget-object v1, Lio/opentelemetry/semconv/ErrorAttributes;->ERROR_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    aput-object v1, v0, v2

    .line 30
    .line 31
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    aput-object v1, v0, v2

    .line 35
    .line 36
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_VERSION:Lio/opentelemetry/api/common/AttributeKey;

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    aput-object v1, v0, v2

    .line 40
    .line 41
    sget-object v1, Lio/opentelemetry/semconv/UrlAttributes;->URL_SCHEME:Lio/opentelemetry/api/common/AttributeKey;

    .line 42
    .line 43
    const/4 v2, 0x6

    .line 44
    aput-object v1, v0, v2

    .line 45
    .line 46
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 51
    .line 52
    .line 53
    return-void
.end method
