.class public final synthetic Lio/opentelemetry/instrumentation/api/instrumenter/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/b;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/b;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->b(Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;)Ljava/util/stream/Stream;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    const-class p0, Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;

    .line 14
    .line 15
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_1
    check-cast p1, Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;

    .line 25
    .line 26
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->c(Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;)Ljava/util/stream/Stream;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_2
    const-class p0, Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;

    .line 32
    .line 33
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;

    .line 40
    .line 41
    return-object p0

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
