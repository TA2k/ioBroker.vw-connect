.class final Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/metrics/data/SummaryPointData;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;

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
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/SummaryPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v0

    .line 4
    invoke-static {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result p0

    .line 5
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v1

    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result v0

    add-int/2addr v0, p0

    .line 6
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getCount()J

    move-result-wide v1

    invoke-static {p0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result p0

    add-int/2addr p0, v0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getSum()D

    move-result-wide v1

    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    move-result v0

    add-int/2addr v0, p0

    .line 8
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->QUANTILE_VALUES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getValues()Ljava/util/List;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileStatelessMarshaler;

    .line 10
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 11
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 12
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object p1

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 13
    invoke-static {v0, p1, v1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p1

    add-int/2addr p1, p0

    return p1
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/SummaryPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/SummaryPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 3
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 4
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getCount()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 5
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getSum()D

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 6
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->QUANTILE_VALUES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getValues()Ljava/util/List;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileStatelessMarshaler;

    .line 8
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 9
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 10
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 11
    invoke-virtual {p1, p0, p2, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/SummaryPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
