.class public final synthetic Lio/opentelemetry/instrumentation/api/semconv/http/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;


# instance fields
.field public final synthetic a:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

.field public final synthetic b:Ljava/util/HashSet;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;Ljava/util/HashSet;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/d;->a:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/d;->b:Ljava/util/HashSet;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/d;->a:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/d;->b:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-static {v0, p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->a(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;Ljava/util/HashSet;Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/context/Context;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
