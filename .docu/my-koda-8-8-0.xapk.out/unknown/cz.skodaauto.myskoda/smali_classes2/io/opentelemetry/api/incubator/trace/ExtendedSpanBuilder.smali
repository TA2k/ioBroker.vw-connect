.class public interface abstract Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/SpanBuilder;


# virtual methods
.method public abstract addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public abstract addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public bridge synthetic addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
    .locals 0

    .line 2
    invoke-super {p0, p1}, Lio/opentelemetry/api/trace/SpanBuilder;->setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    return-object p0
.end method

.method public bridge synthetic setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;"
        }
    .end annotation
.end method

.method public abstract setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public abstract setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public abstract setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public abstract setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 3
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 4
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 5
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setNoParent()Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public bridge synthetic setNoParent()Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setNoParent()Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public bridge synthetic setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setParentFrom(Lio/opentelemetry/context/propagation/ContextPropagators;Ljava/util/Map;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/ContextPropagators;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;"
        }
    .end annotation
.end method

.method public abstract setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public bridge synthetic setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
.end method

.method public setStartTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
    .locals 0

    .line 3
    invoke-super {p0, p1}, Lio/opentelemetry/api/trace/SpanBuilder;->setStartTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    return-object p0
.end method

.method public bridge synthetic setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setStartTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;->setStartTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract startAndCall(Lio/opentelemetry/api/incubator/trace/SpanCallable;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "E:",
            "Ljava/lang/Throwable;",
            ">(",
            "Lio/opentelemetry/api/incubator/trace/SpanCallable<",
            "TT;TE;>;)TT;^TE;"
        }
    .end annotation
.end method

.method public abstract startAndCall(Lio/opentelemetry/api/incubator/trace/SpanCallable;Ljava/util/function/BiConsumer;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "E:",
            "Ljava/lang/Throwable;",
            ">(",
            "Lio/opentelemetry/api/incubator/trace/SpanCallable<",
            "TT;TE;>;",
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/api/trace/Span;",
            "Ljava/lang/Throwable;",
            ">;)TT;^TE;"
        }
    .end annotation
.end method

.method public abstract startAndRun(Lio/opentelemetry/api/incubator/trace/SpanRunnable;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Throwable;",
            ">(",
            "Lio/opentelemetry/api/incubator/trace/SpanRunnable<",
            "TE;>;)V^TE;"
        }
    .end annotation
.end method

.method public abstract startAndRun(Lio/opentelemetry/api/incubator/trace/SpanRunnable;Ljava/util/function/BiConsumer;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Throwable;",
            ">(",
            "Lio/opentelemetry/api/incubator/trace/SpanRunnable<",
            "TE;>;",
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/api/trace/Span;",
            "Ljava/lang/Throwable;",
            ">;)V^TE;"
        }
    .end annotation
.end method
