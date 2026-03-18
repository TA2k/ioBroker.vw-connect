.class public final synthetic Lio/opentelemetry/sdk/metrics/internal/state/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/b;->b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

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
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/b;->a:I

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/b;->b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 11
    .line 12
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->b(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 17
    .line 18
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/b;->b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->f(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
