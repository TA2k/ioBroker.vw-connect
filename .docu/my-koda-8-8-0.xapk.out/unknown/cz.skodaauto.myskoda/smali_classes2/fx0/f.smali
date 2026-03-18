.class public final synthetic Lfx0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfx0/f;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lfx0/f;->b:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lfx0/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object p0, p0, Lfx0/f;->b:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->setEmitExperimentalHttpServerTelemetry(Z)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object p0, p0, Lfx0/f;->b:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 19
    .line 20
    check-cast p1, Ljava/util/List;

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_1
    iget-object p0, p0, Lfx0/f;->b:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 27
    .line 28
    check-cast p1, Ljava/util/List;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_2
    iget-object p0, p0, Lfx0/f;->b:Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 35
    .line 36
    check-cast p1, Ljava/util/Set;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
