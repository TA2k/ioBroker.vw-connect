.class public final Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private exportUnsampledSpans:Z

.field private final spanExporter:Lio/opentelemetry/sdk/trace/export/SpanExporter;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/trace/export/SpanExporter;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;->exportUnsampledSpans:Z

    .line 6
    .line 7
    const-string v0, "spanExporter"

    .line 8
    .line 9
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    check-cast p1, Lio/opentelemetry/sdk/trace/export/SpanExporter;

    .line 13
    .line 14
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;->spanExporter:Lio/opentelemetry/sdk/trace/export/SpanExporter;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;->spanExporter:Lio/opentelemetry/sdk/trace/export/SpanExporter;

    .line 4
    .line 5
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;->exportUnsampledSpans:Z

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;-><init>(Lio/opentelemetry/sdk/trace/export/SpanExporter;Z)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public setExportUnsampledSpans(Z)Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessorBuilder;->exportUnsampledSpans:Z

    .line 2
    .line 3
    return-object p0
.end method
