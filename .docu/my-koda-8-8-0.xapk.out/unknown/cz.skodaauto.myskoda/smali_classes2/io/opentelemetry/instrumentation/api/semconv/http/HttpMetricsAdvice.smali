.class final Lio/opentelemetry/instrumentation/api/semconv/http/HttpMetricsAdvice;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final DURATION_SECONDS_BUCKETS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

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
    .locals 16

    .line 1
    const-wide v0, 0x3f747ae147ae147bL    # 0.005

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    const-wide v0, 0x3f847ae147ae147bL    # 0.01

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    const-wide v0, 0x3f9999999999999aL    # 0.025

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    const-wide v0, 0x3fa999999999999aL    # 0.05

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    const-wide v0, 0x3fb3333333333333L    # 0.075

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 43
    .line 44
    .line 45
    move-result-object v6

    .line 46
    const-wide v0, 0x3fb999999999999aL    # 0.1

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    const-wide/high16 v0, 0x3fd0000000000000L    # 0.25

    .line 56
    .line 57
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    const-wide/high16 v0, 0x3fe0000000000000L    # 0.5

    .line 62
    .line 63
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    const-wide/high16 v0, 0x3fe8000000000000L    # 0.75

    .line 68
    .line 69
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 70
    .line 71
    .line 72
    move-result-object v10

    .line 73
    const-wide/high16 v0, 0x3ff0000000000000L    # 1.0

    .line 74
    .line 75
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 76
    .line 77
    .line 78
    move-result-object v11

    .line 79
    const-wide/high16 v0, 0x4004000000000000L    # 2.5

    .line 80
    .line 81
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 82
    .line 83
    .line 84
    move-result-object v12

    .line 85
    const-wide/high16 v0, 0x4014000000000000L    # 5.0

    .line 86
    .line 87
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 88
    .line 89
    .line 90
    move-result-object v13

    .line 91
    const-wide/high16 v0, 0x401e000000000000L    # 7.5

    .line 92
    .line 93
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 94
    .line 95
    .line 96
    move-result-object v14

    .line 97
    const-wide/high16 v0, 0x4024000000000000L    # 10.0

    .line 98
    .line 99
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 100
    .line 101
    .line 102
    move-result-object v15

    .line 103
    filled-new-array/range {v2 .. v15}, [Ljava/lang/Double;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpMetricsAdvice;->DURATION_SECONDS_BUCKETS:Ljava/util/List;

    .line 116
    .line 117
    const-string v0, "url.template"

    .line 118
    .line 119
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpMetricsAdvice;->URL_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 124
    .line 125
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

.method public static applyClientDurationAdvice(Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

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
    sget-object v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpMetricsAdvice;->URL_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;

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
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method public static applyServerDurationAdvice(Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

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
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 51
    .line 52
    .line 53
    return-void
.end method
