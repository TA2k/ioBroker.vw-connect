.class Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;
.super Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field private extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final lock:Ljava/lang/Object;


# direct methods
.method private constructor <init>(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;)V
    .locals 14
    .param p4    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Lio/opentelemetry/api/common/Value;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p13    # Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/lang/String;",
            "JJ",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/api/logs/Severity;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;",
            ")V"
        }
    .end annotation

    .line 1
    const/4 v12, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-object v1, p1

    .line 4
    move-object/from16 v2, p2

    .line 5
    .line 6
    move-object/from16 v3, p3

    .line 7
    .line 8
    move-object/from16 v13, p4

    .line 9
    .line 10
    move-wide/from16 v4, p5

    .line 11
    .line 12
    move-wide/from16 v6, p7

    .line 13
    .line 14
    move-object/from16 v8, p9

    .line 15
    .line 16
    move-object/from16 v9, p10

    .line 17
    .line 18
    move-object/from16 v10, p11

    .line 19
    .line 20
    move-object/from16 v11, p12

    .line 21
    .line 22
    invoke-direct/range {v0 .. v13}, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;-><init>(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    new-instance p1, Ljava/lang/Object;

    .line 26
    .line 27
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 31
    .line 32
    move-object/from16 p1, p13

    .line 33
    .line 34
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    .line 35
    .line 36
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;)Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;
    .locals 14
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Lio/opentelemetry/api/common/Value;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/lang/String;",
            "JJ",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/api/logs/Severity;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;",
            ")",
            "Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object v2, p1

    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move-wide/from16 v5, p4

    .line 10
    .line 11
    move-wide/from16 v7, p6

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
    invoke-direct/range {v0 .. v13}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;-><init>(Lio/opentelemetry/sdk/logs/LogLimits;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method private getImmutableExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->empty()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;->immutableCopy()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    monitor-exit v0

    .line 21
    return-object p0

    .line 22
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method


# virtual methods
.method public getAttribute(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .locals 0
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
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->getAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public getAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    monitor-enter v0

    .line 3
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Ljava/util/AbstractMap;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    .line 4
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;->get(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;

    move-result-object p0

    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 5
    monitor-exit v0

    return-object p0

    .line 6
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->getExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->asAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->getImmutableExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;"
        }
    .end annotation

    if-eqz p1, :cond_1

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    if-nez p2, :cond_0

    goto :goto_0

    .line 4
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;

    move-result-object p0

    :cond_1
    :goto_0
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;"
        }
    .end annotation

    if-eqz p1, :cond_2

    .line 5
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    if-nez p2, :cond_0

    goto :goto_2

    .line 6
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    monitor-enter v0

    .line 7
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    if-nez v1, :cond_1

    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    .line 9
    invoke-virtual {v1}, Lio/opentelemetry/sdk/logs/LogLimits;->getMaxNumberOfAttributes()I

    move-result v1

    int-to-long v1, v1

    iget-object v3, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->logLimits:Lio/opentelemetry/sdk/logs/LogLimits;

    invoke-virtual {v3}, Lio/opentelemetry/sdk/logs/LogLimits;->getMaxAttributeValueLength()I

    move-result v3

    .line 10
    invoke-static {v1, v2, v3}, Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;->create(JI)Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    move-result-object v1

    iput-object v1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 11
    :cond_1
    :goto_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    invoke-virtual {v1, p1, p2}, Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    monitor-exit v0

    return-object p0

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_2
    :goto_2
    return-object p0
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;
    .locals 0

    .line 2
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic toLogRecordData()Lio/opentelemetry/sdk/logs/data/LogRecordData;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->toLogRecordData()Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;

    move-result-object p0

    return-object p0
.end method

.method public toLogRecordData()Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;
    .locals 15

    .line 2
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->lock:Ljava/lang/Object;

    monitor-enter v1

    .line 3
    :try_start_0
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->resource:Lio/opentelemetry/sdk/resources/Resource;

    iget-object v3, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    iget-object v4, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->eventName:Ljava/lang/String;

    iget-wide v5, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->timestampEpochNanos:J

    iget-wide v7, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->observedTimestampEpochNanos:J

    iget-object v9, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    iget-object v10, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severity:Lio/opentelemetry/api/logs/Severity;

    iget-object v11, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->severityText:Ljava/lang/String;

    iget-object v12, p0, Lio/opentelemetry/sdk/logs/SdkReadWriteLogRecord;->body:Lio/opentelemetry/api/common/Value;

    .line 4
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->getImmutableExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    move-result-object v13

    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/ExtendedSdkReadWriteLogRecord;->extendedAttributes:Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;

    if-nez p0, :cond_0

    const/4 p0, 0x0

    :goto_0
    move v14, p0

    goto :goto_1

    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/ExtendedAttributesMap;->getTotalAddedValues()I

    move-result p0

    goto :goto_0

    .line 6
    :goto_1
    invoke-static/range {v2 .. v14}, Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordData;->create(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/api/incubator/common/ExtendedAttributes;I)Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordData;

    move-result-object p0

    monitor-exit v1

    return-object p0

    :catchall_0
    move-exception v0

    move-object p0, v0

    .line 7
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method
