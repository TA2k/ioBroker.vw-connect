.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;,
        Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Client;
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

.method public static builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V

    return-object v0
.end method

.method public static builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    const/4 v1, 0x0

    invoke-direct {v0, v1, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V

    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    move-result-object p0

    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    move-result-object p0

    return-object p0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 2
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    move-result-object p0

    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    move-result-object p0

    return-object p0
.end method
