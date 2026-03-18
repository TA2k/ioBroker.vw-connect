.class final Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilderImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;


# instance fields
.field private final spanBuilder:Lio/opentelemetry/api/trace/SpanBuilder;


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/trace/SpanBuilder;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilderImpl;->spanBuilder:Lio/opentelemetry/api/trace/SpanBuilder;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilderImpl;->spanBuilder:Lio/opentelemetry/api/trace/SpanBuilder;

    invoke-interface {v0, p1}, Lio/opentelemetry/api/trace/SpanBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/SpanBuilder;

    return-object p0
.end method

.method public addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;
    .locals 1

    .line 2
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilderImpl;->spanBuilder:Lio/opentelemetry/api/trace/SpanBuilder;

    invoke-interface {v0, p1, p2}, Lio/opentelemetry/api/trace/SpanBuilder;->addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;

    return-object p0
.end method
