.class Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field private attributes:Lio/opentelemetry/sdk/internal/AttributesMap;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected final body:Lio/opentelemetry/api/common/Value;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected eventName:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private final lock:Ljava/lang/Object;

.field protected final logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

.field protected final observedTimestampEpochNanos:J

.field protected final resource:Lio/opentelemetry/sdk/resources/Resource;

.field protected final severity:Lio/opentelemetry/api/logs/Severity;

.field protected final severityText:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field protected final spanContext:Lio/opentelemetry/api/trace/SpanContext;

.field protected final timestampEpochNanos:J


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/lang/String;)V
    .locals 1
    .param p10    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Lio/opentelemetry/api/common/Value;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Lio/opentelemetry/sdk/internal/AttributesMap;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p13    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "JJ",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/api/logs/Severity;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/sdk/internal/AttributesMap;",
            "Ljava/lang/String;",
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
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    .line 12
    .line 13
    iput-object p2, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 14
    .line 15
    iput-object p3, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 16
    .line 17
    iput-wide p4, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->timestampEpochNanos:J

    .line 18
    .line 19
    iput-wide p6, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->observedTimestampEpochNanos:J

    .line 20
    .line 21
    iput-object p8, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 22
    .line 23
    iput-object p9, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 24
    .line 25
    iput-object p10, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severityText:Ljava/lang/String;

    .line 26
    .line 27
    iput-object p11, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->body:Lio/opentelemetry/api/common/Value;

    .line 28
    .line 29
    iput-object p13, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->eventName:Ljava/lang/String;

    .line 30
    .line 31
    iput-object p12, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 32
    .line 33
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;
    .locals 14
    .param p9    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Lio/opentelemetry/api/common/Value;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Lio/opentelemetry/sdk/internal/AttributesMap;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "JJ",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/api/logs/Severity;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/sdk/internal/AttributesMap;",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object v2, p1

    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-wide/from16 v4, p3

    .line 8
    .line 9
    move-wide/from16 v6, p5

    .line 10
    .line 11
    move-object/from16 v8, p7

    .line 12
    .line 13
    move-object/from16 v9, p8

    .line 14
    .line 15
    move-object/from16 v10, p9

    .line 16
    .line 17
    move-object/from16 v11, p10

    .line 18
    .line 19
    move-object/from16 v12, p11

    .line 20
    .line 21
    move-object/from16 v13, p12

    .line 22
    .line 23
    invoke-direct/range {v0 .. v13}, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;-><init>(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method private getImmutableAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 5
    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 16
    .line 17
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/AttributesMap;->immutableCopy()Lio/opentelemetry/api/common/Attributes;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    monitor-exit v0

    .line 22
    return-object p0

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    :goto_0
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    monitor-exit v0

    .line 30
    return-object p0

    .line 31
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    throw p0
.end method


# virtual methods
.method public getAttribute(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 5
    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/AttributesMap;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    monitor-exit v0

    .line 22
    return-object p0

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 26
    monitor-exit v0

    .line 27
    return-object p0

    .line 28
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    throw p0
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->getImmutableAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getBodyValue()Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->body:Lio/opentelemetry/api/common/Value;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEventName()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->eventName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public getObservedTimestampEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->observedTimestampEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getSeverity()Lio/opentelemetry/api/logs/Severity;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSeverityText()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severityText:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTimestampEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->timestampEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_2

    .line 12
    .line 13
    if-nez p2, :cond_0

    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-enter v0

    .line 19
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 20
    .line 21
    if-nez v1, :cond_1

    .line 22
    .line 23
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    .line 24
    .line 25
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LogLimits;->getMaxNumberOfAttributes()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    int-to-long v1, v1

    .line 30
    iget-object v3, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    .line 31
    .line 32
    invoke-virtual {v3}, Lio/opentelemetry/sdk/logs/LogLimits;->getMaxAttributeValueLength()I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    invoke-static {v1, v2, v3}, Lio/opentelemetry/sdk/internal/AttributesMap;->create(JI)Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    iput-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    :goto_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 46
    .line 47
    invoke-virtual {v1, p1, p2}, Lio/opentelemetry/sdk/internal/AttributesMap;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    monitor-exit v0

    .line 51
    return-object p0

    .line 52
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    throw p0

    .line 54
    :cond_2
    :goto_2
    return-object p0
.end method

.method public toLogRecordData()Lio/opentelemetry/sdk/logs/data/LogRecordData;
    .locals 15

    .line 1
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 5
    .line 6
    iget-object v3, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 7
    .line 8
    iget-wide v4, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->timestampEpochNanos:J

    .line 9
    .line 10
    iget-wide v6, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->observedTimestampEpochNanos:J

    .line 11
    .line 12
    iget-object v8, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 13
    .line 14
    iget-object v9, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 15
    .line 16
    iget-object v10, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severityText:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v11, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->body:Lio/opentelemetry/api/common/Value;

    .line 19
    .line 20
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->getImmutableAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 21
    .line 22
    .line 23
    move-result-object v12

    .line 24
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 25
    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    :goto_0
    move v13, v0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/AttributesMap;->getTotalAddedValues()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    goto :goto_0

    .line 36
    :goto_1
    iget-object v14, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->eventName:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static/range {v2 .. v14}, Lio/opentelemetry/sdk/logs/SdkLogRecordData;->create(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/api/common/Attributes;ILjava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLogRecordData;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    monitor-exit v1

    .line 43
    return-object p0

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    move-object p0, v0

    .line 46
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    throw p0
.end method
