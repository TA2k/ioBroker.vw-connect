.class final Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "BySpanKey"
.end annotation


# instance fields
.field private final spanKeys:[Lio/opentelemetry/instrumentation/api/internal/SpanKey;


# direct methods
.method public constructor <init>(Ljava/util/Set;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lio/opentelemetry/instrumentation/api/internal/SpanKey;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    new-array v0, v0, [Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 6
    .line 7
    invoke-interface {p1, v0}, Ljava/util/Set;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, [Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 12
    .line 13
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;->spanKeys:[Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public shouldSuppress(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;)Z
    .locals 3

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;->spanKeys:[Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    array-length p2, p0

    .line 4
    const/4 v0, 0x0

    .line 5
    move v1, v0

    .line 6
    :goto_0
    if-ge v1, p2, :cond_1

    .line 7
    .line 8
    aget-object v2, p0, v1

    .line 9
    .line 10
    invoke-virtual {v2, p1}, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    return v0

    .line 17
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;
    .locals 2

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;->spanKeys:[Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    array-length p2, p0

    .line 4
    const/4 v0, 0x0

    .line 5
    :goto_0
    if-ge v0, p2, :cond_0

    .line 6
    .line 7
    aget-object v1, p0, v0

    .line 8
    .line 9
    invoke-virtual {v1, p1, p3}, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    add-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    return-object p1
.end method
