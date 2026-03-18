.class final Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
        "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
        "Ljava/util/List<",
        "Lio/opentelemetry/sdk/metrics/data/MetricData;",
        ">;>;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;

    .line 7
    .line 8
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


# virtual methods
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 2
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;->create(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;

    move-result-object p0

    .line 3
    invoke-virtual {p3, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addData(Ljava/lang/Object;)V

    .line 4
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCOPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    move-result p0

    .line 5
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->METRICS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;

    .line 6
    invoke-static {v0, p2, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p2

    add-int/2addr p2, p0

    .line 7
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/ScopeSpans;->SCHEMA_URL:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getSchemaUrl()Ljava/lang/String;

    move-result-object p1

    .line 9
    invoke-static {p0, p1, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, p2

    return p0
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    check-cast p2, Ljava/util/List;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/Serializer;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 2
    const-class p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;

    .line 3
    invoke-virtual {p4, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getData(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;

    .line 4
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCOPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 5
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->METRICS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;

    invoke-virtual {p1, p0, p3, v0, p4}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 6
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCHEMA_URL:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    invoke-virtual {p2}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getSchemaUrl()Ljava/lang/String;

    move-result-object p2

    .line 8
    invoke-virtual {p1, p0, p2, p4}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    check-cast p3, Ljava/util/List;

    invoke-virtual {p0, p1, p2, p3, p4}, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
