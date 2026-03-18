.class public final synthetic Lio/opentelemetry/exporter/internal/http/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/exporter/internal/http/HttpExporter;

.field public final synthetic c:Lio/opentelemetry/sdk/common/CompletableResultCode;

.field public final synthetic d:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;I)V
    .locals 0

    .line 1
    iput p4, p0, Lio/opentelemetry/exporter/internal/http/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/http/a;->b:Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 4
    .line 5
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/http/a;->c:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 6
    .line 7
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/http/a;->d:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/http/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/a;->d:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;

    .line 7
    .line 8
    check-cast p1, Ljava/lang/Throwable;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/a;->b:Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/a;->c:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 13
    .line 14
    invoke-static {v1, p0, v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->a(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/a;->d:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;

    .line 19
    .line 20
    check-cast p1, Lio/opentelemetry/exporter/internal/http/HttpSender$Response;

    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/a;->b:Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 23
    .line 24
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/a;->c:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 25
    .line 26
    invoke-static {v1, p0, v0, p1}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->b(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
