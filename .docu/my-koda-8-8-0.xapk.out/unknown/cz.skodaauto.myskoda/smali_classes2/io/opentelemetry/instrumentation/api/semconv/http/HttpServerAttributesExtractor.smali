.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;
.super Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor<",
        "TREQUEST;TRESPONSE;",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
        "TREQUEST;TRESPONSE;>;>;",
        "Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;"
    }
.end annotation


# instance fields
.field private final httpRouteGetter:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/context/Context;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final internalClientExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final internalNetworkExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final internalServerExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final internalUrlExtractor:Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    iget-object v1, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 2
    .line 3
    sget-object v2, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;->SERVER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    .line 4
    .line 5
    iget-object v3, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->capturedRequestHeaders:Ljava/util/List;

    .line 6
    .line 7
    iget-object v4, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->capturedResponseHeaders:Ljava/util/List;

    .line 8
    .line 9
    iget-object v5, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->knownMethods:Ljava/util/Set;

    .line 10
    .line 11
    move-object v0, p0

    .line 12
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;Ljava/util/List;Ljava/util/List;Ljava/util/Set;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->buildUrlExtractor()Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalUrlExtractor:Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 20
    .line 21
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->buildNetworkExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalNetworkExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 26
    .line 27
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->buildServerExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalServerExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 32
    .line 33
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->buildClientExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalClientExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;

    .line 38
    .line 39
    iget-object p0, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpRouteGetter:Ljava/util/function/Function;

    .line 40
    .line 41
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->httpRouteGetter:Ljava/util/function/Function;

    .line 42
    .line 43
    return-void
.end method

.method public static builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private userAgent(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 2
    .line 3
    check-cast p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 4
    .line 5
    const-string v0, "user-agent"

    .line 6
    .line 7
    invoke-interface {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->firstHeaderValue(Ljava/util/List;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->HTTP_SERVER:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    return-object p0
.end method

.method public onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
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
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-super/range {p0 .. p5}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalNetworkExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 5
    .line 6
    invoke-virtual {p5, p1, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    sget-object p3, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_ROUTE:Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->httpRouteGetter:Ljava/util/function/Function;

    .line 12
    .line 13
    invoke-interface {p0, p2}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {p1, p3, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    invoke-super {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalUrlExtractor:Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 5
    .line 6
    invoke-virtual {p2, p1, p3}, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalServerExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 10
    .line 11
    invoke-virtual {p2, p1, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->internalClientExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;

    .line 15
    .line 16
    invoke-virtual {p2, p1, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    sget-object p2, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_ROUTE:Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 22
    .line 23
    check-cast v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 24
    .line 25
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;->getHttpRoute(Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    sget-object p2, Lio/opentelemetry/semconv/UserAgentAttributes;->USER_AGENT_ORIGINAL:Lio/opentelemetry/api/common/AttributeKey;

    .line 33
    .line 34
    invoke-direct {p0, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->userAgent(Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method
