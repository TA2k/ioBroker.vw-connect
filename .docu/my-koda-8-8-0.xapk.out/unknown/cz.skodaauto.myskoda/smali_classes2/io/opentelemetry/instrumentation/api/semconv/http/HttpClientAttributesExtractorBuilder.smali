.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
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

.field final httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
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

.field redactQueryParameters:Z

.field resendCountIncrementer:Ljava/util/function/ToIntFunction;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/ToIntFunction<",
            "Lio/opentelemetry/context/Context;",
            ">;"
        }
    .end annotation
.end field

.field final serverAddressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/Experimental;->internalSetRedactHttpClientQueryParameters(Ljava/util/function/BiConsumer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
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
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->capturedRequestHeaders:Ljava/util/List;

    .line 7
    .line 8
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->capturedResponseHeaders:Ljava/util/List;

    .line 9
    .line 10
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/HttpConstants;->KNOWN_METHODS:Ljava/util/Set;

    .line 11
    .line 12
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->knownMethods:Ljava/util/Set;

    .line 13
    .line 14
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/c;

    .line 15
    .line 16
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->resendCountIncrementer:Ljava/util/function/ToIntFunction;

    .line 20
    .line 21
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 22
    .line 23
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ServerAddressAndPortExtractor;

    .line 24
    .line 25
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/http/HostAddressAndPortExtractor;

    .line 26
    .line 27
    invoke-direct {v1, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HostAddressAndPortExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {v0, p1, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ServerAddressAndPortExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->serverAddressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 34
    .line 35
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->lambda$static$0(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;Ljava/lang/Boolean;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$static$0(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->redactQueryParameters:Z

    .line 6
    .line 7
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
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;)V

    .line 4
    .line 5
    .line 6
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
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

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
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->serverAddressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->capturedRequestHeaders:Ljava/util/List;

    return-object p0
.end method

.method public setCapturedRequestHeaders(Ljava/util/List;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->capturedResponseHeaders:Ljava/util/List;

    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/List;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0, p1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->knownMethods:Ljava/util/Set;

    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setResendCountIncrementer(Ljava/util/function/ToIntFunction;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/ToIntFunction<",
            "Lio/opentelemetry/context/Context;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->resendCountIncrementer:Ljava/util/function/ToIntFunction;

    .line 2
    .line 3
    return-object p0
.end method
