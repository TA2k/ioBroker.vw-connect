.class final Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final instrumentationScope:Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;

.field private final metricMarshalers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field private final schemaUrlUtf8:[B


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;[BLjava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;",
            "[B",
            "Ljava/util/List<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-static {p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->calculateSize(Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;[BLjava/util/List;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->instrumentationScope:Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->schemaUrlUtf8:[B

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->metricMarshalers:Ljava/util/List;

    .line 13
    .line 14
    return-void
.end method

.method private static calculateSize(Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;[BLjava/util/List;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;",
            "[B",
            "Ljava/util/List<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;)I"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCOPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCHEMA_URL:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->METRICS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    return p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCOPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->instrumentationScope:Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->METRICS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->metricMarshalers:Ljava/util/List;

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ScopeMetrics;->SCHEMA_URL:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/InstrumentationScopeMetricsMarshaler;->schemaUrlUtf8:[B

    .line 18
    .line 19
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
