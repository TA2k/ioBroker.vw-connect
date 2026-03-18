.class public interface abstract Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
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

.annotation runtime Ljava/lang/FunctionalInterface;
.end annotation


# direct methods
.method public static synthetic a(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->lambda$alwaysInternal$0(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static alwaysClient()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/g;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static alwaysConsumer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/g;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static alwaysInternal()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/g;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static alwaysProducer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/g;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static alwaysServer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static synthetic b(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->lambda$alwaysServer$2(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->lambda$alwaysClient$1(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->lambda$alwaysProducer$3(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->lambda$alwaysConsumer$4(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$alwaysClient$1(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/trace/SpanKind;->CLIENT:Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    return-object p0
.end method

.method private static synthetic lambda$alwaysConsumer$4(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/trace/SpanKind;->CONSUMER:Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    return-object p0
.end method

.method private static synthetic lambda$alwaysInternal$0(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/trace/SpanKind;->INTERNAL:Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    return-object p0
.end method

.method private static synthetic lambda$alwaysProducer$3(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/trace/SpanKind;->PRODUCER:Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    return-object p0
.end method

.method private static synthetic lambda$alwaysServer$2(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/trace/SpanKind;->SERVER:Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public abstract extract(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Lio/opentelemetry/api/trace/SpanKind;"
        }
    .end annotation
.end method
