.class public interface abstract Lio/opentelemetry/api/trace/SpanBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static synthetic a(Lio/opentelemetry/api/trace/SpanBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/trace/SpanBuilder;->lambda$setAllAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$setAllAttributes$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/SpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
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
    const/4 v1, 0x2

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

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;I)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;I)",
            "Lio/opentelemetry/api/trace/SpanBuilder;"
        }
    .end annotation

    int-to-long v0, p2

    .line 1
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/trace/SpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/trace/SpanBuilder;"
        }
    .end annotation
.end method

.method public abstract setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setNoParent()Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public abstract setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/SpanBuilder;
.end method

.method public setStartTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 4

    if-nez p1, :cond_0

    return-object p0

    .line 1
    :cond_0
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    invoke-virtual {p1}, Ljava/time/Instant;->getEpochSecond()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    invoke-virtual {p1}, Ljava/time/Instant;->getNano()I

    move-result p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 3
    invoke-interface {p0, v0, v1, p1}, Lio/opentelemetry/api/trace/SpanBuilder;->setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract startSpan()Lio/opentelemetry/api/trace/Span;
.end method
