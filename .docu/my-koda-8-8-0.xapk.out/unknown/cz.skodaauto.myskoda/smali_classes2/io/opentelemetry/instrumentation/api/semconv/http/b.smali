.class public final synthetic Lio/opentelemetry/instrumentation/api/semconv/http/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/b;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/b;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 7
    .line 8
    check-cast p2, Ljava/util/function/Function;

    .line 9
    .line 10
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->b(Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 15
    .line 16
    check-cast p2, Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->a(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;Ljava/lang/Boolean;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
