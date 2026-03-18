.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;
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
.field final clientGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
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

.field final serverGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field urlTemplateExtractor:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "TREQUEST;",
            "Ljava/lang/String;",
            ">;"
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
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/Experimental;->internalSetUrlTemplateExtractor(Ljava/util/function/BiConsumer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V
    .locals 2
    .param p1    # Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;*>;",
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
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->knownMethods:Ljava/util/Set;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/a;

    .line 9
    .line 10
    const/4 v1, 0x6

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/a;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->urlTemplateExtractor:Ljava/util/function/Function;

    .line 15
    .line 16
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->clientGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 17
    .line 18
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->serverGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 19
    .line 20
    return-void
.end method

.method public static synthetic a(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->lambda$new$0(Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;Ljava/util/function/Function;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->lambda$static$1(Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;Ljava/util/function/Function;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$new$0(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method private static synthetic lambda$static$1(Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;Ljava/util/function/Function;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->urlTemplateExtractor:Ljava/util/function/Function;

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->knownMethods:Ljava/util/Set;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->clientGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v2, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Client;

    .line 13
    .line 14
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->urlTemplateExtractor:Ljava/util/function/Function;

    .line 15
    .line 16
    invoke-direct {v2, v1, v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Client;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Ljava/util/Set;Ljava/util/function/Function;)V

    .line 17
    .line 18
    .line 19
    return-object v2

    .line 20
    :cond_0
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->serverGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 23
    .line 24
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    check-cast p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 28
    .line 29
    invoke-direct {v1, p0, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;Ljava/util/Set;)V

    .line 30
    .line 31
    .line 32
    return-object v1
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0, p1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->knownMethods:Ljava/util/Set;

    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    move-result-object p0

    return-object p0
.end method
