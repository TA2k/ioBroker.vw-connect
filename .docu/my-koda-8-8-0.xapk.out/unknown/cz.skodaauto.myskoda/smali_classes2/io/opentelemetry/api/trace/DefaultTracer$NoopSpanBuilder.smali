.class final Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/SpanBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/trace/DefaultTracer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "NoopSpanBuilder"
.end annotation


# instance fields
.field private spanContext:Lio/opentelemetry/api/trace/SpanContext;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create()Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public bridge synthetic addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 4
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 3
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 4
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 5
    return-object p0
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 6
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 7
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 8
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 9
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 10
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setNoParent()Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 1

    .line 2
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    return-object p0
.end method

.method public bridge synthetic setNoParent()Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setNoParent()Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    if-nez p1, :cond_0

    .line 2
    const-string p1, "context is null"

    invoke-static {p1}, Lio/opentelemetry/api/internal/ApiUsageLogger;->log(Ljava/lang/String;)V

    return-object p0

    .line 3
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    move-result-object p1

    invoke-interface {p1}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    return-object p0
.end method

.method public bridge synthetic setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public startSpan()Lio/opentelemetry/api/trace/Span;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lio/opentelemetry/api/trace/Span;->current()Lio/opentelemetry/api/trace/Span;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 14
    .line 15
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/api/trace/DefaultTracer$NoopSpanBuilder;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 16
    .line 17
    invoke-static {p0}, Lio/opentelemetry/api/trace/Span;->wrap(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
