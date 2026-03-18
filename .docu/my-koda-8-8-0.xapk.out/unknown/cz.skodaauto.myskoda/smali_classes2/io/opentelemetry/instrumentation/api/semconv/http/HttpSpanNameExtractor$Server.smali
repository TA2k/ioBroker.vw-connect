.class final Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Server"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field

.field private final knownMethods:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;Ljava/util/Set;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;->knownMethods:Ljava/util/Set;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public extract(Ljava/lang/Object;)Ljava/lang/String;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestMethod(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "HTTP"

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    return-object v1

    .line 12
    :cond_0
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;->knownMethods:Ljava/util/Set;

    .line 13
    .line 14
    invoke-interface {v2, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-nez v2, :cond_1

    .line 19
    .line 20
    move-object v0, v1

    .line 21
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor$Server;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 22
    .line 23
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;->getHttpRoute(Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    if-nez p0, :cond_2

    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_2
    const-string p1, " "

    .line 31
    .line 32
    invoke-static {v0, p1, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
