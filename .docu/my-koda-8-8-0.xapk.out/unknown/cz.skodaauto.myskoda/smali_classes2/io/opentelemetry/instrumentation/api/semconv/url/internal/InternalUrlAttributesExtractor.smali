.class public final Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;
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
.field private final alternateSchemeProvider:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "TREQUEST;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;Ljava/util/function/Function;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter<",
            "TREQUEST;>;",
            "Ljava/util/function/Function<",
            "TREQUEST;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->alternateSchemeProvider:Ljava/util/function/Function;

    .line 7
    .line 8
    return-void
.end method

.method private getUrlScheme(Ljava/lang/Object;)Ljava/lang/String;
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
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->alternateSchemeProvider:Ljava/util/function/Function;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/String;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;->getUrlScheme(Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    return-object v0
.end method


# virtual methods
.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p2}, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->getUrlScheme(Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;

    .line 6
    .line 7
    invoke-interface {v1, p2}, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;->getUrlPath(Ljava/lang/Object;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;

    .line 12
    .line 13
    invoke-interface {p0, p2}, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;->getUrlQuery(Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p2, Lio/opentelemetry/semconv/UrlAttributes;->URL_SCHEME:Lio/opentelemetry/api/common/AttributeKey;

    .line 18
    .line 19
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    sget-object p2, Lio/opentelemetry/semconv/UrlAttributes;->URL_PATH:Lio/opentelemetry/api/common/AttributeKey;

    .line 23
    .line 24
    invoke-static {p1, p2, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    sget-object p2, Lio/opentelemetry/semconv/UrlAttributes;->URL_QUERY:Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method
