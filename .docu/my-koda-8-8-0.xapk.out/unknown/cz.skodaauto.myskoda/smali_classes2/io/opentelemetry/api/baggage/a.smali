.class public final synthetic Lio/opentelemetry/api/baggage/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/api/baggage/a;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/api/baggage/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/api/baggage/a;->c:Ljava/lang/Object;

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
    iget v0, p0, Lio/opentelemetry/api/baggage/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/api/baggage/a;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/api/baggage/a;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/util/Map;

    .line 13
    .line 14
    check-cast p1, Lio/opentelemetry/api/common/Attributes;

    .line 15
    .line 16
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 17
    .line 18
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->a(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Ljava/util/Map;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/api/baggage/a;->b:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Lio/opentelemetry/context/Context;

    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/api/baggage/a;->c:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ljava/util/function/BiConsumer;

    .line 29
    .line 30
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/context/Context;->d(Lio/opentelemetry/context/Context;Ljava/util/function/BiConsumer;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_1
    iget-object v0, p0, Lio/opentelemetry/api/baggage/a;->b:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Ljava/lang/String;

    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/api/baggage/a;->c:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, [Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 41
    .line 42
    check-cast p1, Ljava/lang/String;

    .line 43
    .line 44
    check-cast p2, Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 45
    .line 46
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/api/baggage/Baggage;->b(Ljava/lang/String;[Lio/opentelemetry/api/baggage/BaggageEntry;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
