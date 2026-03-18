.class public final synthetic Lio/opentelemetry/sdk/metrics/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/sdk/metrics/f;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/f;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 11
    .line 12
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->d(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    check-cast p0, Ljava/util/List;

    .line 18
    .line 19
    check-cast p1, Ljava/util/Map$Entry;

    .line 20
    .line 21
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->b(Ljava/util/List;Ljava/util/Map$Entry;)Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
