.class public final synthetic Lio/opentelemetry/instrumentation/api/internal/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/instrumentation/api/internal/f;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/instrumentation/api/internal/f;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/lang/String;

    .line 9
    .line 10
    check-cast p1, Ljava/lang/String;

    .line 11
    .line 12
    check-cast p2, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 13
    .line 14
    invoke-static {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->b(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 19
    .line 20
    check-cast p1, Ljava/lang/String;

    .line 21
    .line 22
    check-cast p2, Ljava/util/concurrent/atomic/AtomicLong;

    .line 23
    .line 24
    invoke-static {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->e(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicLong;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_1
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 29
    .line 30
    check-cast p1, Ljava/lang/String;

    .line 31
    .line 32
    check-cast p2, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;

    .line 33
    .line 34
    invoke-static {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->c(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
