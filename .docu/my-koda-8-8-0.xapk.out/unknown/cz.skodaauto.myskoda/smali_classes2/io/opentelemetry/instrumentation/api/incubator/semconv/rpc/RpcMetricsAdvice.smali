.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final RPC_GRPC_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private static final RPC_METRICS_ATTRIBUTE_KEYS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-string v0, "rpc.grpc.status_code"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;->RPC_GRPC_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const/16 v1, 0x8

    .line 10
    .line 11
    new-array v1, v1, [Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    sget-object v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcCommonAttributesExtractor;->RPC_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    aput-object v2, v1, v3

    .line 17
    .line 18
    sget-object v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcCommonAttributesExtractor;->RPC_SERVICE:Lio/opentelemetry/api/common/AttributeKey;

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    aput-object v2, v1, v3

    .line 22
    .line 23
    sget-object v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcCommonAttributesExtractor;->RPC_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    aput-object v2, v1, v3

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    aput-object v0, v1, v2

    .line 30
    .line 31
    sget-object v0, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    aput-object v0, v1, v2

    .line 35
    .line 36
    sget-object v0, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_TRANSPORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    aput-object v0, v1, v2

    .line 40
    .line 41
    sget-object v0, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 42
    .line 43
    const/4 v2, 0x6

    .line 44
    aput-object v0, v1, v2

    .line 45
    .line 46
    sget-object v0, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 47
    .line 48
    const/4 v2, 0x7

    .line 49
    aput-object v0, v1, v2

    .line 50
    .line 51
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;->RPC_METRICS_ATTRIBUTE_KEYS:Ljava/util/List;

    .line 56
    .line 57
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
    .locals 1

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
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;->RPC_METRICS_ATTRIBUTE_KEYS:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static applyClientRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V
    .locals 1

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
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;->RPC_METRICS_ATTRIBUTE_KEYS:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static applyServerDurationAdvice(Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V
    .locals 1

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
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;->RPC_METRICS_ATTRIBUTE_KEYS:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static applyServerRequestSizeAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V
    .locals 1

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
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcMetricsAdvice;->RPC_METRICS_ATTRIBUTE_KEYS:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 11
    .line 12
    .line 13
    return-void
.end method
