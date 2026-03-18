.class public final Lio/opentelemetry/exporter/logging/internal/ConsoleSpanExporterProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/autoconfigure/spi/traces/ConfigurableSpanExporterProvider;


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
.method public createExporter(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;)Lio/opentelemetry/sdk/trace/export/SpanExporter;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/logging/LoggingSpanExporter;->create()Lio/opentelemetry/exporter/logging/LoggingSpanExporter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "console"

    .line 2
    .line 3
    return-object p0
.end method
