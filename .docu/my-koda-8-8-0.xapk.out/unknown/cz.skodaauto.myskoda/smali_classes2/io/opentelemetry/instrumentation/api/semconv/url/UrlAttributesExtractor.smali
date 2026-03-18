.class public final Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# instance fields
.field private final internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 5
    .line 6
    new-instance v1, Lfx0/d;

    .line 7
    .line 8
    const/16 v2, 0xf

    .line 9
    .line 10
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-direct {v0, p1, v1}, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;Ljava/util/function/Function;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;->internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 17
    .line 18
    return-void
.end method

.method public static synthetic a(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;->lambda$new$0(Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static synthetic lambda$new$0(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method


# virtual methods
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
    return-void
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/url/UrlAttributesExtractor;->internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p3}, Lio/opentelemetry/instrumentation/api/semconv/url/internal/InternalUrlAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
