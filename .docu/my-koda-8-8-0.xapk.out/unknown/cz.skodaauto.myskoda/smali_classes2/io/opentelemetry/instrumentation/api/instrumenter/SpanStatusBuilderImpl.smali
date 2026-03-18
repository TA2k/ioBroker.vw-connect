.class final Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilderImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;


# instance fields
.field private final span:Lio/opentelemetry/api/trace/Span;


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/trace/Span;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilderImpl;->span:Lio/opentelemetry/api/trace/Span;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilderImpl;->span:Lio/opentelemetry/api/trace/Span;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2}, Lio/opentelemetry/api/trace/Span;->setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
