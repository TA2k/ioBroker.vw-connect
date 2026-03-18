.class public Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpClientInstrumenterBuilderFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final INSTRUMENTATION_NAME:Ljava/lang/String; = "io.opentelemetry.okhttp-3.0"


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

.method public static create(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/OpenTelemetry;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "Ld01/b0;",
            "Ld01/t0;",
            ">;"
        }
    .end annotation

    .line 1
    const-string v0, "io.opentelemetry.okhttp-3.0"

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->INSTANCE:Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->create(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
