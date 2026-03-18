.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter<",
            "-TREQUEST;-TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final statusCodeConverter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter<",
            "-TREQUEST;-TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;->statusCodeConverter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    .line 7
    .line 8
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "-TREQUEST;-TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;

    sget-object v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;->CLIENT:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;)V

    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "-TREQUEST;-TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;

    sget-object v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;->SERVER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;)V

    return-object v0
.end method


# virtual methods
.method public extract(Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 1
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            ")V"
        }
    .end annotation

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 4
    .line 5
    invoke-interface {v0, p2, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpResponseStatusCode(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;->statusCodeConverter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p0, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;->isError(I)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    sget-object p0, Lio/opentelemetry/api/trace/StatusCode;->ERROR:Lio/opentelemetry/api/trace/StatusCode;

    .line 24
    .line 25
    invoke-interface {p1, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;->setStatus(Lio/opentelemetry/api/trace/StatusCode;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;->getDefault()Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-interface {p0, p1, p2, p3, p4}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;->extract(Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
