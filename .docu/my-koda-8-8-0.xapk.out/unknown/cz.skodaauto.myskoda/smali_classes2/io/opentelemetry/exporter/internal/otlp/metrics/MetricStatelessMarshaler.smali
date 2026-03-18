.class final Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/metrics/data/MetricData;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;

.field private static final METRIC_MARSHALERS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/metrics/data/MetricDataType;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;

    .line 7
    .line 8
    new-instance v0, Ljava/util/EnumMap;

    .line 9
    .line 10
    const-class v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->METRIC_MARSHALERS:Ljava/util/Map;

    .line 16
    .line 17
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->LONG_GAUGE:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 18
    .line 19
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$1;

    .line 20
    .line 21
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$1;-><init>()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->DOUBLE_GAUGE:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 28
    .line 29
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$2;

    .line 30
    .line 31
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$2;-><init>()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->LONG_SUM:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 38
    .line 39
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$3;

    .line 40
    .line 41
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$3;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->DOUBLE_SUM:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 48
    .line 49
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$4;

    .line 50
    .line 51
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$4;-><init>()V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->SUMMARY:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 58
    .line 59
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$5;

    .line 60
    .line 61
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$5;-><init>()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->HISTOGRAM:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 68
    .line 69
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$6;

    .line 70
    .line 71
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$6;-><init>()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    sget-object v1, Lio/opentelemetry/sdk/metrics/data/MetricDataType;->EXPONENTIAL_HISTOGRAM:Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    .line 78
    .line 79
    new-instance v2, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$7;

    .line 80
    .line 81
    invoke-direct {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$7;-><init>()V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0, v1, v2}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
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
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3

    .line 2
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->METRIC_MARSHALERS:Ljava/util/Map;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getType()Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    move-result-object v0

    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;

    if-nez p0, :cond_0

    const/4 p0, 0x0

    return p0

    .line 3
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result v0

    .line 4
    sget-object v1, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->DESCRIPTION:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 5
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getDescription()Ljava/lang/String;

    move-result-object v2

    .line 6
    invoke-static {v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result v1

    add-int/2addr v1, v0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->UNIT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getUnit()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result v0

    add-int/2addr v0, v1

    .line 8
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    return p0
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/MetricData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2

    .line 2
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->METRIC_MARSHALERS:Ljava/util/Map;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getType()Lio/opentelemetry/sdk/metrics/data/MetricDataType;

    move-result-object v0

    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;

    if-nez p0, :cond_0

    return-void

    .line 3
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 4
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->DESCRIPTION:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getDescription()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 5
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->UNIT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getUnit()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 6
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/MetricData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
