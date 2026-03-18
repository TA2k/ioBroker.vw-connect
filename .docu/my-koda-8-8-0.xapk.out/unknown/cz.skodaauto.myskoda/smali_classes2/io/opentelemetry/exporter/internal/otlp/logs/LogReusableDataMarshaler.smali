.class public Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final doExport:Ljava/util/function/BiFunction;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/BiFunction<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            "Ljava/lang/Integer;",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;",
            ">;"
        }
    .end annotation
.end field

.field private final marshalerPool:Ljava/util/Deque;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Deque<",
            "Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;",
            ">;"
        }
    .end annotation
.end field

.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/export/MemoryMode;Ljava/util/function/BiFunction;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            "Ljava/util/function/BiFunction<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            "Ljava/lang/Integer;",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentLinkedDeque;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentLinkedDeque;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->marshalerPool:Ljava/util/Deque;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 12
    .line 13
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->doExport:Ljava/util/function/BiFunction;

    .line 14
    .line 15
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->lambda$export$0(Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$export$0(Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->reset()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->marshalerPool:Ljava/util/Deque;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/Deque;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;)",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 4
    .line 5
    if-ne v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->marshalerPool:Ljava/util/Deque;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/Deque;->poll()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;

    .line 18
    .line 19
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;-><init>()V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;->initialize(Ljava/util/Collection;)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->doExport:Ljava/util/function/BiFunction;

    .line 26
    .line 27
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-interface {v1, v0, p1}, Ljava/util/function/BiFunction;->apply(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    check-cast p1, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 40
    .line 41
    new-instance v1, Lh0/h0;

    .line 42
    .line 43
    const/16 v2, 0xb

    .line 44
    .line 45
    invoke-direct {v1, v2, p0, v0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, v1}, Lio/opentelemetry/sdk/common/CompletableResultCode;->whenComplete(Ljava/lang/Runnable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LogsRequestMarshaler;->create(Ljava/util/Collection;)Lio/opentelemetry/exporter/internal/otlp/logs/LogsRequestMarshaler;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->doExport:Ljava/util/function/BiFunction;

    .line 58
    .line 59
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-interface {p0, v0, p1}, Ljava/util/function/BiFunction;->apply(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 72
    .line 73
    return-object p0
.end method

.method public getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 2
    .line 3
    return-object p0
.end method
