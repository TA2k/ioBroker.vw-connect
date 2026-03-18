.class final Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;
    }
.end annotation


# instance fields
.field private final value:Lio/opentelemetry/exporter/internal/marshal/Marshaler;


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;)V
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;->calculateSize(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;->value:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->KVLIST_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public static create(Ljava/util/List;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/KeyValue;",
            ">;)",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    new-array v1, v1, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v0, :cond_0

    .line 13
    .line 14
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    check-cast v3, Lio/opentelemetry/api/common/KeyValue;

    .line 19
    .line 20
    invoke-static {v3}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForKeyValue(Lio/opentelemetry/api/common/KeyValue;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    aput-object v3, v1, v2

    .line 25
    .line 26
    add-int/lit8 v2, v2, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;

    .line 30
    .line 31
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;

    .line 32
    .line 33
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 34
    .line 35
    .line 36
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;-><init>(Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler$KeyValueListMarshaler;)V

    .line 37
    .line 38
    .line 39
    return-object p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->KVLIST_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueMarshaler;->value:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
