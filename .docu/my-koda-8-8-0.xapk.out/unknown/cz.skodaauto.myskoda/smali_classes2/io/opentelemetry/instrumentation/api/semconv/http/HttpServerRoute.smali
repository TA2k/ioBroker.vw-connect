.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;,
        Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$OneArgAdapter;
    }
.end annotation


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

.method public static builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static get(Lio/opentelemetry/context/Context;)Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->getRoute()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method private static isBetterRoute(Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;Ljava/lang/String;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->getRoute()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    move p0, v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    :goto_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-le p1, p0, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_1
    return v0
.end method

.method public static update(Lio/opentelemetry/context/Context;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBiGetter;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 5
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBiGetter<",
            "TT;TU;>;TT;TU;)V"
        }
    .end annotation

    .line 3
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_1

    .line 4
    :cond_0
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->getSpan()Lio/opentelemetry/api/trace/Span;

    move-result-object v1

    if-nez v1, :cond_1

    goto :goto_1

    .line 5
    :cond_1
    iget-boolean v2, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->useFirst:Z

    if-nez v2, :cond_2

    iget v2, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->order:I

    .line 6
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->getUpdatedBySourceOrder()I

    move-result v3

    if-ne v2, v3, :cond_2

    const/4 v2, 0x1

    goto :goto_0

    :cond_2
    const/4 v2, 0x0

    .line 7
    :goto_0
    iget v3, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->order:I

    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->getUpdatedBySourceOrder()I

    move-result v4

    if-gt v3, v4, :cond_3

    if-eqz v2, :cond_5

    .line 8
    :cond_3
    invoke-interface {p2, p0, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBiGetter;->get(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_5

    .line 9
    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    move-result p3

    if-nez p3, :cond_5

    if-eqz v2, :cond_4

    .line 10
    invoke-static {v0, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->isBetterRoute(Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;Ljava/lang/String;)Z

    move-result p3

    if-eqz p3, :cond_5

    .line 11
    :cond_4
    invoke-static {v1, v0, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->updateSpanName(Lio/opentelemetry/api/trace/Span;Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;Ljava/lang/String;)V

    .line 12
    iget p1, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->order:I

    invoke-virtual {v0, p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->update(Lio/opentelemetry/context/Context;ILjava/lang/String;)V

    :cond_5
    :goto_1
    return-void
.end method

.method public static update(Lio/opentelemetry/context/Context;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteGetter;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteGetter<",
            "TT;>;TT;)V"
        }
    .end annotation

    .line 2
    invoke-static {}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$OneArgAdapter;->getInstance()Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$OneArgAdapter;

    move-result-object v0

    invoke-static {p0, p1, v0, p3, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->update(Lio/opentelemetry/context/Context;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBiGetter;Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public static update(Lio/opentelemetry/context/Context;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;->access$000()Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;

    move-result-object v0

    invoke-static {p0, p1, v0, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->update(Lio/opentelemetry/context/Context;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteGetter;Ljava/lang/Object;)V

    return-void
.end method

.method private static updateSpanName(Lio/opentelemetry/api/trace/Span;Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->getMethod()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p1, " "

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-interface {p0, p1}, Lio/opentelemetry/api/trace/Span;->updateName(Ljava/lang/String;)Lio/opentelemetry/api/trace/Span;

    .line 26
    .line 27
    .line 28
    return-void
.end method
