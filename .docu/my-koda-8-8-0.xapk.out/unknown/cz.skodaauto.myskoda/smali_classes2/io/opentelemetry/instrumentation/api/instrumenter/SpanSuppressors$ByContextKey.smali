.class Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$ByContextKey;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ByContextKey"
.end annotation


# instance fields
.field private final delegate:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$ByContextKey;->delegate:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public shouldSuppress(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;)Z
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/api/internal/InstrumentationUtil;->shouldSuppressInstrumentation(Lio/opentelemetry/context/Context;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$ByContextKey;->delegate:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 10
    .line 11
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;->shouldSuppress(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$ByContextKey;->delegate:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;->storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
