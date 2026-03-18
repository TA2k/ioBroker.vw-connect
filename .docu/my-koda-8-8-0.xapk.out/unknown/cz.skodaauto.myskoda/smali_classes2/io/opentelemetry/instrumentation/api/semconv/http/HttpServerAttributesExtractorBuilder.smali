.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field capturedRequestHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field capturedResponseHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field final clientAddressPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field final httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field httpRouteGetter:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/context/Context;",
            "Ljava/lang/String;",
            ">;"
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

.field final serverAddressPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->capturedRequestHeaders:Ljava/util/List;

    .line 7
    .line 8
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->capturedResponseHeaders:Ljava/util/List;

    .line 9
    .line 10
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/HttpConstants;->KNOWN_METHODS:Ljava/util/Set;

    .line 11
    .line 12
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->knownMethods:Ljava/util/Set;

    .line 13
    .line 14
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/a;

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpRouteGetter:Ljava/util/function/Function;

    .line 21
    .line 22
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 23
    .line 24
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;

    .line 25
    .line 26
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;

    .line 27
    .line 28
    invoke-direct {v1, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V

    .line 29
    .line 30
    .line 31
    invoke-direct {v0, p1, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->clientAddressPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 35
    .line 36
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/ForwardedHostAddressAndPortExtractor;

    .line 37
    .line 38
    invoke-direct {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/ForwardedHostAddressAndPortExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;)V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->serverAddressPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public buildClientExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->clientAddressPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;Z)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public buildNetworkExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, p0, v1, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;ZZ)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public buildServerExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->serverAddressPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public buildUrlExtractor()Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 4
    .line 5
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/http/ForwardedUrlSchemeProvider;

    .line 6
    .line 7
    invoke-direct {v1, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/ForwardedUrlSchemeProvider;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->capturedRequestHeaders:Ljava/util/List;

    return-object p0
.end method

.method public setCapturedRequestHeaders(Ljava/util/List;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->capturedResponseHeaders:Ljava/util/List;

    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/List;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setHttpRouteGetter(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/context/Context;",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->httpRouteGetter:Ljava/util/function/Function;

    .line 2
    .line 3
    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0, p1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->knownMethods:Ljava/util/Set;

    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    move-result-object p0

    return-object p0
.end method
