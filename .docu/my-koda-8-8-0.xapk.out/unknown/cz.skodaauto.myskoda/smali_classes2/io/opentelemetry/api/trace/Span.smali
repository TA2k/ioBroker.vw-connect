.class public interface abstract Lio/opentelemetry/api/trace/Span;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/ImplicitContextKeyed;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static synthetic a(Lio/opentelemetry/api/trace/Span;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->lambda$setAllAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static current()Lio/opentelemetry/api/trace/Span;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lio/opentelemetry/api/trace/SpanContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 6
    .line 7
    invoke-interface {v0, v1}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lio/opentelemetry/api/trace/Span;

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    invoke-static {}, Lio/opentelemetry/api/trace/Span;->getInvalid()Lio/opentelemetry/api/trace/Span;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :cond_0
    return-object v0
.end method

.method public static fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "context is null"

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/internal/ApiUsageLogger;->log(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/api/trace/Span;->getInvalid()Lio/opentelemetry/api/trace/Span;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_0
    sget-object v0, Lio/opentelemetry/api/trace/SpanContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lio/opentelemetry/api/trace/Span;

    .line 20
    .line 21
    if-nez p0, :cond_1

    .line 22
    .line 23
    invoke-static {}, Lio/opentelemetry/api/trace/Span;->getInvalid()Lio/opentelemetry/api/trace/Span;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :cond_1
    return-object p0
.end method

.method public static fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "context is null"

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/internal/ApiUsageLogger;->log(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return-object p0

    .line 10
    :cond_0
    sget-object v0, Lio/opentelemetry/api/trace/SpanContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lio/opentelemetry/api/trace/Span;

    .line 17
    .line 18
    return-object p0
.end method

.method public static getInvalid()Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/PropagatedSpan;->INVALID:Lio/opentelemetry/api/trace/PropagatedSpan;

    .line 2
    .line 3
    return-object v0
.end method

.method private synthetic lambda$setAllAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static wrap(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "context is null"

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/internal/ApiUsageLogger;->log(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/api/trace/Span;->getInvalid()Lio/opentelemetry/api/trace/Span;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_0
    invoke-static {p0}, Lio/opentelemetry/api/trace/PropagatedSpan;->create(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public addEvent(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/api/trace/Span;->addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public addEvent(Ljava/lang/String;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;
    .locals 6

    .line 2
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v2

    move-object v0, p0

    move-object v1, p1

    move-wide v3, p2

    move-object v5, p4

    invoke-interface/range {v0 .. v5}, Lio/opentelemetry/api/trace/Span;->addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public abstract addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
.end method

.method public abstract addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;
.end method

.method public addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/time/Instant;)Lio/opentelemetry/api/trace/Span;
    .locals 10

    if-nez p3, :cond_0

    .line 7
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0

    .line 8
    :cond_0
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 9
    invoke-virtual {p3}, Ljava/time/Instant;->getEpochSecond()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    invoke-virtual {p3}, Ljava/time/Instant;->getNano()I

    move-result p3

    int-to-long v2, p3

    add-long v7, v0, v2

    sget-object v9, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    move-object v4, p0

    move-object v5, p1

    move-object v6, p2

    .line 10
    invoke-interface/range {v4 .. v9}, Lio/opentelemetry/api/trace/Span;->addEvent(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public addEvent(Ljava/lang/String;Ljava/time/Instant;)Lio/opentelemetry/api/trace/Span;
    .locals 4

    if-nez p2, :cond_0

    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/api/trace/Span;->addEvent(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0

    .line 4
    :cond_0
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 5
    invoke-virtual {p2}, Ljava/time/Instant;->getEpochSecond()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    invoke-virtual {p2}, Ljava/time/Instant;->getNano()I

    move-result p2

    int-to-long v2, p2

    add-long/2addr v0, v2

    sget-object p2, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 6
    invoke-interface {p0, p1, v0, v1, p2}, Lio/opentelemetry/api/trace/Span;->addEvent(Ljava/lang/String;JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 2
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/api/trace/Span;->addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 1
    return-object p0
.end method

.method public abstract end()V
.end method

.method public abstract end(JLjava/util/concurrent/TimeUnit;)V
.end method

.method public end(Ljava/time/Instant;)V
    .locals 4

    if-nez p1, :cond_0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/trace/Span;->end()V

    return-void

    .line 2
    :cond_0
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p1}, Ljava/time/Instant;->getEpochSecond()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/time/Instant;->getNano()I

    move-result p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-interface {p0, v0, v1, p1}, Lio/opentelemetry/api/trace/Span;->end(JLjava/util/concurrent/TimeUnit;)V

    return-void
.end method

.method public abstract getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
.end method

.method public abstract isRecording()Z
.end method

.method public recordException(Ljava/lang/Throwable;)Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/api/trace/Span;->recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public abstract recordException(Ljava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
.end method

.method public setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

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
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/logs/a;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p1, v0}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    :goto_0
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;I)Lio/opentelemetry/api/trace/Span;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;I)",
            "Lio/opentelemetry/api/trace/Span;"
        }
    .end annotation

    int-to-long v0, p2

    .line 5
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public abstract setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;
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
            "Lio/opentelemetry/api/trace/Span;"
        }
    .end annotation
.end method

.method public setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 3
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 2
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
    .locals 0
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/Span;
    .locals 0

    .line 4
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public setStatus(Lio/opentelemetry/api/trace/StatusCode;)Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    const-string v0, ""

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/api/trace/Span;->setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;

    move-result-object p0

    return-object p0
.end method

.method public abstract setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
.end method

.method public storeInContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/SpanContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, v0, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public abstract updateName(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;
.end method
