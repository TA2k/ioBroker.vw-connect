.class Lio/opentelemetry/sdk/logs/SdkLogger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/Logger;


# static fields
.field private static final INCUBATOR_AVAILABLE:Z

.field private static final NOOP_LOGGER:Lio/opentelemetry/api/logs/Logger;


# instance fields
.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field protected volatile loggerEnabled:Z

.field private final loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/api/logs/LoggerProvider;->noop()Lio/opentelemetry/api/logs/LoggerProvider;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "noop"

    .line 6
    .line 7
    invoke-interface {v0, v1}, Lio/opentelemetry/api/logs/LoggerProvider;->get(Ljava/lang/String;)Lio/opentelemetry/api/logs/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/logs/SdkLogger;->NOOP_LOGGER:Lio/opentelemetry/api/logs/Logger;

    .line 12
    .line 13
    :try_start_0
    sget v0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLoggerProvider;->d:I
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    goto :goto_0

    .line 17
    :catch_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    sput-boolean v0, Lio/opentelemetry/sdk/logs/SdkLogger;->INCUBATOR_AVAILABLE:Z

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 7
    .line 8
    invoke-virtual {p3}, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;->isEnabled()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iput-boolean p1, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerEnabled:Z

    .line 13
    .line 14
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)Lio/opentelemetry/sdk/logs/SdkLogger;
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/sdk/logs/SdkLogger;->INCUBATOR_AVAILABLE:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/logs/IncubatingUtil;->createExtendedLogger(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)Lio/opentelemetry/sdk/logs/SdkLogger;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/logs/SdkLogger;

    .line 11
    .line 12
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/logs/SdkLogger;-><init>(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method


# virtual methods
.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEnabled(Lio/opentelemetry/api/logs/Severity;Lio/opentelemetry/context/Context;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public logRecordBuilder()Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerEnabled:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    sget-boolean v0, Lio/opentelemetry/sdk/logs/SdkLogger;->INCUBATOR_AVAILABLE:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 12
    .line 13
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/logs/IncubatingUtil;->createExtendedLogRecordBuilder(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    .line 19
    .line 20
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 23
    .line 24
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;-><init>(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    :cond_1
    sget-object p0, Lio/opentelemetry/sdk/logs/SdkLogger;->NOOP_LOGGER:Lio/opentelemetry/api/logs/Logger;

    .line 29
    .line 30
    invoke-interface {p0}, Lio/opentelemetry/api/logs/Logger;->logRecordBuilder()Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public updateLoggerConfig(Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;->isEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput-boolean p1, p0, Lio/opentelemetry/sdk/logs/SdkLogger;->loggerEnabled:Z

    .line 6
    .line 7
    return-void
.end method
