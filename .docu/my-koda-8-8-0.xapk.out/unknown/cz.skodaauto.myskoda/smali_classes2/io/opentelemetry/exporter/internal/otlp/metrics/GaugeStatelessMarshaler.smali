.class final Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/metrics/data/GaugeData<",
        "+",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">;>;"
    }
.end annotation


# static fields
.field private static final DATA_POINT_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

.field private static final DATA_POINT_WRITER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;

    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->DATA_POINT_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 13
    .line 14
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->DATA_POINT_WRITER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 19
    .line 20
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
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/GaugeData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/data/GaugeData<",
            "+",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Gauge;->DATA_POINTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/Data;->getPoints()Ljava/util/Collection;

    move-result-object p1

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointStatelessMarshaler;

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->DATA_POINT_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 4
    invoke-static {p0, p1, v0, p2, v1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/Collection;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;)I

    move-result p0

    return p0
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/GaugeData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/GaugeData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/GaugeData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/Serializer;",
            "Lio/opentelemetry/sdk/metrics/data/GaugeData<",
            "+",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 2
    sget-object v1, Lio/opentelemetry/proto/metrics/v1/internal/Gauge;->DATA_POINTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/Data;->getPoints()Ljava/util/Collection;

    move-result-object v2

    sget-object v3, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointStatelessMarshaler;

    sget-object v5, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->DATA_POINT_WRITER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    move-object v0, p1

    move-object v4, p3

    .line 4
    invoke-virtual/range {v0 .. v5}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/Collection;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/GaugeData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/GaugeStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/GaugeData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
