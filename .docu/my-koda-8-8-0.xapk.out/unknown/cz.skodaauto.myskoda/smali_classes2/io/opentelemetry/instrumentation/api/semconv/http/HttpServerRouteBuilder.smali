.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field final getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field

.field knownMethods:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/HttpConstants;->KNOWN_METHODS:Ljava/util/Set;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->knownMethods:Ljava/util/Set;

    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 9
    .line 10
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;Ljava/util/HashSet;Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->lambda$build$0(Ljava/util/Set;Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private synthetic lambda$build$0(Ljava/util/Set;Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    invoke-static {p2}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    .line 2
    .line 3
    .line 4
    move-result-object p4

    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    return-object p2

    .line 8
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 9
    .line 10
    invoke-interface {p0, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestMethod(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    invoke-interface {p1, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-nez p1, :cond_2

    .line 21
    .line 22
    :cond_1
    const-string p0, "HTTP"

    .line 23
    .line 24
    :cond_2
    const/4 p1, 0x0

    .line 25
    const/4 p3, 0x0

    .line 26
    invoke-static {p0, p1, p3}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->create(Ljava/lang/String;Ljava/lang/String;I)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-interface {p2, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ImplicitContextKeyed;)Lio/opentelemetry/context/Context;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method


# virtual methods
.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->knownMethods:Ljava/util/Set;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/http/d;

    .line 9
    .line 10
    invoke-direct {v1, p0, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/d;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;Ljava/util/HashSet;)V

    .line 11
    .line 12
    .line 13
    return-object v1
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0, p1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->knownMethods:Ljava/util/Set;

    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    move-result-object p0

    return-object p0
.end method
