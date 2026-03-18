.class public final Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "Ld01/b0;",
            "Ld01/t0;",
            ">;"
        }
    .end annotation
.end field

.field private final openTelemetry:Lio/opentelemetry/api/OpenTelemetry;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/Experimental;->internalSetEmitExperimentalTelemetry(Ljava/util/function/BiConsumer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/api/OpenTelemetry;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpClientInstrumenterBuilderFactory;->create(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 9
    .line 10
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->lambda$static$0(Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;Ljava/lang/Boolean;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$static$0(Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->setEmitExperimentalHttpClientTelemetry(Z)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "Ld01/b0;",
            "Ld01/t0;",
            ">;)",
            "Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 10
    .line 11
    invoke-interface {p0}, Lio/opentelemetry/api/OpenTelemetry;->getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/propagation/ContextPropagators;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setSpanNameExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "Ld01/b0;",
            ">;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "Ld01/b0;",
            ">;>;)",
            "Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->builder:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->setSpanNameExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
