.class public final synthetic Lio/opentelemetry/sdk/metrics/internal/state/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

.field public final synthetic c:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;I)V
    .locals 0

    .line 1
    iput p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 4
    .line 5
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->c:Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->a:I

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 9
    .line 10
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->c:Ljava/util/List;

    .line 13
    .line 14
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->c(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 19
    .line 20
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->b:Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/c;->c:Ljava/util/List;

    .line 23
    .line 24
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->d(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/data/PointData;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
