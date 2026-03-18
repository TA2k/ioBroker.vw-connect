.class public Lio/opentelemetry/exporter/otlp/internal/OtlpHttpSpanExporterComponentProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/autoconfigure/spi/internal/ComponentProvider;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public create(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/sdk/trace/export/SpanExporter;
    .locals 12

    .line 2
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpHttpSpanExporterComponentProvider;->httpBuilder()Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;

    move-result-object p0

    .line 3
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v2, Lex0/l;

    const/4 v0, 0x0

    invoke-direct {v2, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 4
    new-instance v3, Lex0/l;

    const/4 v0, 0x1

    invoke-direct {v3, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 5
    new-instance v4, Lex0/m;

    const/4 v0, 0x0

    invoke-direct {v4, p0, v0}, Lex0/m;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 6
    new-instance v5, Lex0/l;

    const/4 v0, 0x2

    invoke-direct {v5, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 7
    new-instance v6, Lex0/l;

    const/4 v0, 0x3

    invoke-direct {v6, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 8
    new-instance v7, Lex0/l;

    const/4 v0, 0x4

    invoke-direct {v7, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 9
    new-instance v8, Lex0/m;

    const/4 v0, 0x1

    invoke-direct {v8, p0, v0}, Lex0/m;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 10
    new-instance v9, Lex0/l;

    const/4 v0, 0x5

    invoke-direct {v9, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    .line 11
    new-instance v10, Lex0/l;

    const/4 v0, 0x6

    invoke-direct {v10, p0, v0}, Lex0/l;-><init>(Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;I)V

    const/4 v11, 0x1

    .line 12
    const-string v0, "traces"

    move-object v1, p1

    invoke-static/range {v0 .. v11}, Lio/opentelemetry/exporter/otlp/internal/OtlpDeclarativeConfigUtil;->configureOtlpExporterBuilder(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Z)V

    .line 13
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporter;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic create(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/otlp/internal/OtlpHttpSpanExporterComponentProvider;->create(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/sdk/trace/export/SpanExporter;

    move-result-object p0

    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "otlp_http"

    .line 2
    .line 3
    return-object p0
.end method

.method public getType()Ljava/lang/Class;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "Lio/opentelemetry/sdk/trace/export/SpanExporter;",
            ">;"
        }
    .end annotation

    .line 1
    const-class p0, Lio/opentelemetry/sdk/trace/export/SpanExporter;

    .line 2
    .line 3
    return-object p0
.end method

.method public httpBuilder()Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporter;->builder()Lio/opentelemetry/exporter/otlp/http/trace/OtlpHttpSpanExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
