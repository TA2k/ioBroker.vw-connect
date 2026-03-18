.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "GenericDbClientSpanNameExtractor"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter<",
            "TREQUEST;*>;)V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;)V

    return-void
.end method


# virtual methods
.method public extract(Ljava/lang/Object;)Ljava/lang/String;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getDbNamespace(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 8
    .line 9
    invoke-interface {v1, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;->getDbOperationName(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-virtual {p0, v0, p1, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;->computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
