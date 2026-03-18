.class final Lio/opentelemetry/sdk/logs/LoggerSharedState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final clock:Lio/opentelemetry/sdk/common/Clock;

.field private final exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

.field private final lock:Ljava/lang/Object;

.field private final logLimitsSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            ">;"
        }
    .end annotation
.end field

.field private final logRecordProcessor:Lio/opentelemetry/sdk/logs/LogRecordProcessor;

.field private final resource:Lio/opentelemetry/sdk/resources/Resource;

.field private volatile shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/logs/LogRecordProcessor;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            ">;",
            "Lio/opentelemetry/sdk/logs/LogRecordProcessor;",
            "Lio/opentelemetry/sdk/common/Clock;",
            "Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->lock:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 13
    .line 14
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 15
    .line 16
    iput-object p2, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->logLimitsSupplier:Ljava/util/function/Supplier;

    .line 17
    .line 18
    iput-object p3, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->logRecordProcessor:Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 19
    .line 20
    iput-object p4, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 21
    .line 22
    iput-object p5, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public getClock()Lio/opentelemetry/sdk/common/Clock;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    return-object p0
.end method

.method public getExceptionAttributeResolver()Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 2
    .line 3
    return-object p0
.end method

.method public getLogLimits()Lio/opentelemetry/sdk/logs/LogLimits;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->logLimitsSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/logs/LogLimits;

    .line 8
    .line 9
    return-object p0
.end method

.method public getLogRecordProcessor()Lio/opentelemetry/sdk/logs/LogRecordProcessor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->logRecordProcessor:Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object p0
.end method

.method public hasBeenShutdown()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 9
    .line 10
    monitor-exit v0

    .line 11
    return-object p0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->logRecordProcessor:Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 15
    .line 16
    invoke-interface {v1}, Lio/opentelemetry/sdk/logs/LogRecordProcessor;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iput-object v1, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 23
    .line 24
    monitor-exit v0

    .line 25
    return-object p0

    .line 26
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method
