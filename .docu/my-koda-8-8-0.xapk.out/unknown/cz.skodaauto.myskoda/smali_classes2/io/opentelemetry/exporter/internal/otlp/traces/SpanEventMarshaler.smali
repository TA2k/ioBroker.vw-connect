.class final Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMPTY:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;


# instance fields
.field private final attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final droppedAttributesCount:I

.field private final epochNanos:J

.field private final name:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 3
    .line 4
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->EMPTY:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 5
    .line 6
    return-void
.end method

.method private constructor <init>(J[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I)V
    .locals 1

    .line 1
    invoke-static {p1, p2, p3, p4, p5}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->calculateSize(J[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->epochNanos:J

    .line 9
    .line 10
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->name:[B

    .line 11
    .line 12
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 13
    .line 14
    iput p5, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->droppedAttributesCount:I

    .line 15
    .line 16
    return-void
.end method

.method private static calculateSize(J[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/trace/data/EventData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getEpochNanos()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-static {v3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-static {v4}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getTotalAttributeCount()I

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    sub-int/2addr v5, p0

    .line 36
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;-><init>(J[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I)V

    .line 37
    .line 38
    .line 39
    return-object v0
.end method

.method public static createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->EMPTY:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 v1, 0x0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Lio/opentelemetry/sdk/trace/data/EventData;

    .line 32
    .line 33
    add-int/lit8 v3, v1, 0x1

    .line 34
    .line 35
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->create(Lio/opentelemetry/sdk/trace/data/EventData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    aput-object v2, v0, v1

    .line 40
    .line 41
    move v1, v3

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->epochNanos:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->name:[B

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget p0, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->droppedAttributesCount:I

    .line 25
    .line 26
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
