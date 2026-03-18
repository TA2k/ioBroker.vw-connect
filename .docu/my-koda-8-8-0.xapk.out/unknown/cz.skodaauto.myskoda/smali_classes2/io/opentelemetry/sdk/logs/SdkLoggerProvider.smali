.class public final Lio/opentelemetry/sdk/logs/SdkLoggerProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/LoggerProvider;
.implements Ljava/io/Closeable;


# static fields
.field static final DEFAULT_LOGGER_NAME:Ljava/lang/String; = "unknown"

.field private static final LOGGER:Ljava/util/logging/Logger;


# instance fields
.field private final isNoopLogRecordProcessor:Z

.field private final loggerComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/logs/SdkLogger;",
            ">;"
        }
    .end annotation
.end field

.field private loggerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/logs/internal/LoggerConfig;",
            ">;"
        }
    .end annotation
.end field

.field private final sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Ljava/util/List;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/internal/ScopeConfigurator;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            ">;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/logs/LogRecordProcessor;",
            ">;",
            "Lio/opentelemetry/sdk/common/Clock;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/logs/internal/LoggerConfig;",
            ">;",
            "Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p3}, Lio/opentelemetry/sdk/logs/LogRecordProcessor;->composite(Ljava/lang/Iterable;)Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 5
    .line 6
    .line 7
    move-result-object v3

    .line 8
    new-instance v0, Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    move-object v2, p2

    .line 12
    move-object v4, p4

    .line 13
    move-object v5, p6

    .line 14
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/logs/LoggerSharedState;-><init>(Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/logs/LogRecordProcessor;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 18
    .line 19
    new-instance p1, Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 20
    .line 21
    new-instance p2, Lio/opentelemetry/sdk/logs/d;

    .line 22
    .line 23
    invoke-direct {p2, p0}, Lio/opentelemetry/sdk/logs/d;-><init>(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p1, p2}, Lio/opentelemetry/sdk/internal/ComponentRegistry;-><init>(Ljava/util/function/Function;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 30
    .line 31
    iput-object p5, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 32
    .line 33
    instance-of p1, v3, Lio/opentelemetry/sdk/logs/NoopLogRecordProcessor;

    .line 34
    .line 35
    iput-boolean p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->isNoopLogRecordProcessor:Z

    .line 36
    .line 37
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/SdkLogger;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->lambda$new$0(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/SdkLogger;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;Lio/opentelemetry/sdk/logs/SdkLogger;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->lambda$setLoggerConfigurator$1(Lio/opentelemetry/sdk/logs/SdkLogger;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder()Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private getLoggerConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/internal/LoggerConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;->defaultConfig()Lio/opentelemetry/sdk/logs/internal/LoggerConfig;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :cond_0
    return-object p0
.end method

.method private static instrumentationNameOrDefault(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    return-object p0

    .line 11
    :cond_1
    :goto_0
    sget-object p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "Logger requested without instrumentation scope name."

    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string p0, "unknown"

    .line 19
    .line 20
    return-object p0
.end method

.method private synthetic lambda$new$0(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/SdkLogger;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->getLoggerConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/internal/LoggerConfig;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {v0, p1, p0}, Lio/opentelemetry/sdk/logs/SdkLogger;->create(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)Lio/opentelemetry/sdk/logs/SdkLogger;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private synthetic lambda$setLoggerConfigurator$1(Lio/opentelemetry/sdk/logs/SdkLogger;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/SdkLogger;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->getLoggerConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/internal/LoggerConfig;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/logs/SdkLogger;->updateLoggerConfig(Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-wide/16 v0, 0xa

    .line 6
    .line 7
    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1, v2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->join(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getLogRecordProcessor()Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/LogRecordProcessor;->forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public get(Ljava/lang/String;)Lio/opentelemetry/api/logs/Logger;
    .locals 2

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 2
    .line 3
    invoke-static {p1}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->instrumentationNameOrDefault(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0, p1, v0, v0, v1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->get(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lio/opentelemetry/api/logs/Logger;

    .line 17
    .line 18
    return-object p0
.end method

.method public loggerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/logs/LoggerBuilder;
    .locals 1

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->isNoopLogRecordProcessor:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lio/opentelemetry/api/logs/LoggerProvider;->noop()Lio/opentelemetry/api/logs/LoggerProvider;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {p0, p1}, Lio/opentelemetry/api/logs/LoggerProvider;->loggerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/logs/LoggerBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;

    .line 15
    .line 16
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 17
    .line 18
    invoke-static {p1}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->instrumentationNameOrDefault(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;-><init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public setLoggerConfigurator(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/logs/internal/LoggerConfig;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 2
    .line 3
    iget-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 4
    .line 5
    invoke-virtual {p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->getComponents()Ljava/util/Collection;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance v0, Lio/opentelemetry/sdk/logs/c;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/logs/c;-><init>(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p1, v0}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->hasBeenShutdown()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->LOGGER:Ljava/util/logging/Logger;

    .line 10
    .line 11
    sget-object v0, Ljava/util/logging/Level;->INFO:Ljava/util/logging/Level;

    .line 12
    .line 13
    const-string v1, "Calling shutdown() multiple times."

    .line 14
    .line 15
    invoke-virtual {p0, v0, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SdkLoggerProvider{clock="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 9
    .line 10
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getClock()Lio/opentelemetry/sdk/common/Clock;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", resource="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 23
    .line 24
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", logLimits="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 37
    .line 38
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getLogLimits()Lio/opentelemetry/sdk/logs/LogLimits;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, ", logRecordProcessor="

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->sharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 51
    .line 52
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getLogRecordProcessor()Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", loggerConfigurator="

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->loggerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 65
    .line 66
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const/16 p0, 0x7d

    .line 70
    .line 71
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0
.end method
