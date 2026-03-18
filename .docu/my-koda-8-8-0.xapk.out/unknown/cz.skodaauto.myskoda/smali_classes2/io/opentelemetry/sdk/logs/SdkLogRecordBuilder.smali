.class Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/LogRecordBuilder;


# instance fields
.field private attributes:Lio/opentelemetry/sdk/internal/AttributesMap;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected body:Lio/opentelemetry/api/common/Value;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected context:Lio/opentelemetry/context/Context;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected eventName:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field protected final logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

.field protected final loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

.field protected observedTimestampEpochNanos:J

.field protected severity:Lio/opentelemetry/api/logs/Severity;

.field protected severityText:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected timestampEpochNanos:J


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/logs/LoggerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lio/opentelemetry/api/logs/Severity;->UNDEFINED_SEVERITY_NUMBER:Lio/opentelemetry/api/logs/Severity;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 9
    .line 10
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getLogLimits()Lio/opentelemetry/sdk/logs/LogLimits;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    .line 15
    .line 16
    iput-object p2, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public emit()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->hasBeenShutdown()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    iget-object v1, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->context:Lio/opentelemetry/context/Context;

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :cond_1
    iget-wide v2, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->observedTimestampEpochNanos:J

    .line 21
    .line 22
    const-wide/16 v4, 0x0

    .line 23
    .line 24
    cmp-long v4, v2, v4

    .line 25
    .line 26
    if-nez v4, :cond_2

    .line 27
    .line 28
    iget-object v2, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 29
    .line 30
    invoke-virtual {v2}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getClock()Lio/opentelemetry/sdk/common/Clock;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    invoke-interface {v2}, Lio/opentelemetry/sdk/common/Clock;->now()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    :cond_2
    move-wide v9, v2

    .line 39
    iget-object v2, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 40
    .line 41
    invoke-virtual {v2}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getLogRecordProcessor()Lio/opentelemetry/sdk/logs/LogRecordProcessor;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    iget-object v3, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 46
    .line 47
    invoke-virtual {v3}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getLogLimits()Lio/opentelemetry/sdk/logs/LogLimits;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    iget-object v3, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->loggerSharedState:Lio/opentelemetry/sdk/logs/LoggerSharedState;

    .line 52
    .line 53
    invoke-virtual {v3}, Lio/opentelemetry/sdk/logs/LoggerSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    iget-object v6, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 58
    .line 59
    iget-wide v7, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->timestampEpochNanos:J

    .line 60
    .line 61
    invoke-static {v1}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-interface {v3}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 66
    .line 67
    .line 68
    move-result-object v11

    .line 69
    iget-object v12, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 70
    .line 71
    iget-object v13, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->severityText:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v14, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->body:Lio/opentelemetry/api/common/Value;

    .line 74
    .line 75
    iget-object v15, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 76
    .line 77
    iget-object v0, v0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->eventName:Ljava/lang/String;

    .line 78
    .line 79
    move-object/from16 v16, v0

    .line 80
    .line 81
    invoke-static/range {v4 .. v16}, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->create(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-interface {v2, v1, v0}, Lio/opentelemetry/sdk/logs/LogRecordProcessor;->onEmit(Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;)V

    .line 86
    .line 87
    .line 88
    return-void
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 3
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;"
        }
    .end annotation

    if-eqz p1, :cond_2

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    if-nez p2, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    if-nez v0, :cond_1

    .line 4
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    .line 5
    invoke-virtual {v0}, Lio/opentelemetry/sdk/logs/LogLimits;->getMaxNumberOfAttributes()I

    move-result v0

    int-to-long v0, v0

    iget-object v2, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    invoke-virtual {v2}, Lio/opentelemetry/sdk/logs/LogLimits;->getMaxAttributeValueLength()I

    move-result v2

    .line 6
    invoke-static {v0, v1, v2}, Lio/opentelemetry/sdk/internal/AttributesMap;->create(JI)Lio/opentelemetry/sdk/internal/AttributesMap;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 7
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/internal/AttributesMap;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    :goto_0
    return-object p0
.end method

.method public bridge synthetic setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setBody(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setBody(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;"
        }
    .end annotation

    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->body:Lio/opentelemetry/api/common/Value;

    return-object p0
.end method

.method public setBody(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0

    .line 3
    invoke-static {p1}, Lio/opentelemetry/api/common/Value;->of(Ljava/lang/String;)Lio/opentelemetry/api/common/Value;

    move-result-object p1

    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0

    .line 2
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->context:Lio/opentelemetry/context/Context;

    return-object p0
.end method

.method public bridge synthetic setEventName(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setEventName(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setEventName(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0

    .line 2
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->eventName:Ljava/lang/String;

    return-object p0
.end method

.method public setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p1

    iput-wide p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->observedTimestampEpochNanos:J

    return-object p0
.end method

.method public setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 4

    .line 2
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 3
    invoke-virtual {p1}, Ljava/time/Instant;->getEpochSecond()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/time/Instant;->getNano()I

    move-result p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->observedTimestampEpochNanos:J

    return-object p0
.end method

.method public bridge synthetic setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0

    .line 2
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->severity:Lio/opentelemetry/api/logs/Severity;

    return-object p0
.end method

.method public bridge synthetic setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setSeverityText(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setSeverityText(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0

    .line 2
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->severityText:Ljava/lang/String;

    return-object p0
.end method

.method public bridge synthetic setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 0

    .line 3
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p1

    iput-wide p1, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->timestampEpochNanos:J

    return-object p0
.end method

.method public setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;
    .locals 4

    .line 4
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 5
    invoke-virtual {p1}, Ljava/time/Instant;->getEpochSecond()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/time/Instant;->getNano()I

    move-result p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lio/opentelemetry/sdk/logs/SdkLogRecordBuilder;->timestampEpochNanos:J

    return-object p0
.end method
