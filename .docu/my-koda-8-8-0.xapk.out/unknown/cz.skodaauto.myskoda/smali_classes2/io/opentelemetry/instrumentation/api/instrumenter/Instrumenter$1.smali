.class Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public startAndEnd(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;
    .locals 0
    .param p4    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p5    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<RQ:",
            "Ljava/lang/Object;",
            "RS:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TRQ;TRS;>;",
            "Lio/opentelemetry/context/Context;",
            "TRQ;TRS;",
            "Ljava/lang/Throwable;",
            "Ljava/time/Instant;",
            "Ljava/time/Instant;",
            ")",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    invoke-virtual/range {p1 .. p7}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->startAndEnd(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public suppressSpan(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->access$000(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->extract(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->access$100(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-static {}, Lio/opentelemetry/api/trace/Span;->getInvalid()Lio/opentelemetry/api/trace/Span;

    .line 14
    .line 15
    .line 16
    move-result-object p3

    .line 17
    invoke-interface {p1, p2, p0, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;->storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
