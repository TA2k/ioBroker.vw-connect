.class public final Lio/opentelemetry/instrumentation/api/internal/PropagatorBasedSpanLinksExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/context/propagation/TextMapGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final propagator:Lio/opentelemetry/context/propagation/TextMapPropagator;


# direct methods
.method public constructor <init>(Lio/opentelemetry/context/propagation/TextMapPropagator;Lio/opentelemetry/context/propagation/TextMapGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapPropagator;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/PropagatorBasedSpanLinksExtractor;->propagator:Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/internal/PropagatorBasedSpanLinksExtractor;->getter:Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public extract(Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/PropagatorBasedSpanLinksExtractor;->propagator:Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/PropagatorBasedSpanLinksExtractor;->getter:Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 4
    .line 5
    invoke-interface {v0, p2, p3, p0}, Lio/opentelemetry/context/propagation/TextMapPropagator;->extract(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/context/Context;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {p0}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p1, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;

    .line 18
    .line 19
    .line 20
    return-void
.end method
