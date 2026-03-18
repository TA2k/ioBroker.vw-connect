.class public interface abstract Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/LogRecordBuilder;


# direct methods
.method public static synthetic a(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->lambda$setAllAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->lambda$setAllAttributes$1(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$setAllAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$setAllAttributes$1(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 2

    if-eqz p1, :cond_1

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    new-instance v0, Lio/opentelemetry/api/incubator/logs/a;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/incubator/logs/a;-><init>(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;I)V

    invoke-interface {p1, v0}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    :cond_1
    :goto_0
    return-object p0
.end method

.method public setAllAttributes(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 2

    if-eqz p1, :cond_1

    .line 4
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 5
    :cond_0
    new-instance v0, Lio/opentelemetry/api/incubator/logs/a;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/incubator/logs/a;-><init>(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;I)V

    invoke-interface {p1, v0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->forEach(Ljava/util/function/BiConsumer;)V

    :cond_1
    :goto_0
    return-object p0
.end method

.method public bridge synthetic setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
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
            "Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;"
        }
    .end annotation
.end method

.method public abstract setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;"
        }
    .end annotation
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;"
        }
    .end annotation

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->asString()Ljava/lang/String;

    move-result-object p1

    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setBody(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    return-object p0
.end method

.method public abstract setBody(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setBody(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setBody(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setEventName(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setEventName(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setEventName(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setException(Ljava/lang/Throwable;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public abstract setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public abstract setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public abstract setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method
