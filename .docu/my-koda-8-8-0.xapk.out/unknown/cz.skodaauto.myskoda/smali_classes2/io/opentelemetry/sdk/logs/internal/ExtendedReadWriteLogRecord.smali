.class public interface abstract Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;


# direct methods
.method public static synthetic a(Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;->lambda$setAllAttributes$0(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$setAllAttributes$0(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;->setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract getAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;
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
.end method

.method public abstract getExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
.end method

.method public setAllAttributes(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->isEmpty()Z

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
    new-instance v0, Lio/opentelemetry/api/logs/a;

    .line 11
    .line 12
    const/4 v1, 0x6

    .line 13
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/logs/a;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p1, v0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    :goto_0
    return-object p0
.end method

.method public abstract setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;"
        }
    .end annotation
.end method

.method public bridge synthetic toLogRecordData()Lio/opentelemetry/sdk/logs/data/LogRecordData;
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;->toLogRecordData()Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;

    move-result-object p0

    return-object p0
.end method

.method public abstract toLogRecordData()Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;
.end method
