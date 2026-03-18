.class public final synthetic Lio/opentelemetry/api/baggage/propagation/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/StringBuilder;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/StringBuilder;)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/api/baggage/propagation/a;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/api/baggage/propagation/a;->b:Ljava/lang/StringBuilder;

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
    iget v0, p0, Lio/opentelemetry/api/baggage/propagation/a;->a:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/String;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p2, Ljava/lang/String;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/api/baggage/propagation/a;->b:Ljava/lang/StringBuilder;

    .line 11
    .line 12
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->a(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    check-cast p2, Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 17
    .line 18
    iget-object p0, p0, Lio/opentelemetry/api/baggage/propagation/a;->b:Ljava/lang/StringBuilder;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->a(Ljava/lang/StringBuilder;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V

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
