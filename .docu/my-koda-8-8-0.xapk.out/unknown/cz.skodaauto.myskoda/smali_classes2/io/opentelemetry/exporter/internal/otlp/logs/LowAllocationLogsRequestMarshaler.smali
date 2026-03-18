.class public final Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/Marshaler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final RESOURCE_LOG_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

.field private static final RESOURCE_LOG_WRITER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;


# instance fields
.field private final context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

.field private resourceAndScopeMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;>;>;"
        }
    .end annotation
.end field

.field private size:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->RESOURCE_LOG_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->RESOURCE_LOG_WRITER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 5
    .line 6
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 10
    .line 11
    return-void
.end method

.method private static calculateSize(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Ljava/util/Map;)I
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;>;>;)I"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/proto/collector/logs/v1/internal/ExportLogsServiceRequest;->RESOURCE_LOGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/logs/ResourceLogsStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/logs/ResourceLogsStatelessMarshaler;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->RESOURCE_LOG_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 6
    .line 7
    invoke-static {v0, p1, v1, p0, v2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/Map;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method private static groupByResourceAndScope(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Ljava/util/Collection;)Ljava/util/Map;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;)",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;>;>;"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/logs/a;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/otlp/logs/a;-><init>(I)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/logs/a;

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/otlp/logs/a;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1, v0, v1, p0}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->groupByResourceAndScope(Ljava/util/Collection;Ljava/util/function/Function;Ljava/util/function/Function;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)Ljava/util/Map;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method


# virtual methods
.method public getBinarySerializedSize()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->size:I

    .line 2
    .line 3
    return p0
.end method

.method public initialize(Ljava/util/Collection;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->groupByResourceAndScope(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Ljava/util/Collection;)Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->resourceAndScopeMap:Ljava/util/Map;

    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 10
    .line 11
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->calculateSize(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Ljava/util/Map;)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    iput p1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->size:I

    .line 16
    .line 17
    return-void
.end method

.method public reset()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->reset()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->resetReadIndex()V

    .line 4
    .line 5
    .line 6
    sget-object v2, Lio/opentelemetry/proto/collector/logs/v1/internal/ExportLogsServiceRequest;->RESOURCE_LOGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    .line 8
    iget-object v3, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->resourceAndScopeMap:Ljava/util/Map;

    .line 9
    .line 10
    sget-object v4, Lio/opentelemetry/exporter/internal/otlp/logs/ResourceLogsStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/logs/ResourceLogsStatelessMarshaler;

    .line 11
    .line 12
    iget-object v5, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 13
    .line 14
    sget-object v6, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->RESOURCE_LOG_WRITER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    invoke-virtual/range {v1 .. v6}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/Map;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
