.class public final synthetic Lfx0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lfx0/a;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget p0, p0, Lfx0/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 7
    .line 8
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->unsetActiveReader()V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 13
    .line 14
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->a(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_1
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 19
    .line 20
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->b(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
