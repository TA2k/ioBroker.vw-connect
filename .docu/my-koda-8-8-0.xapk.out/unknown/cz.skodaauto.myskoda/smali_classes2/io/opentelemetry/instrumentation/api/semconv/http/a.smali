.class public final synthetic Lio/opentelemetry/instrumentation/api/semconv/http/a;
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
    iput p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/a;->a:I

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
    iget p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->a(Ljava/lang/Object;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    check-cast p1, Lio/opentelemetry/api/metrics/Meter;

    .line 12
    .line 13
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerMetrics;->a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerMetrics;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    check-cast p1, Lio/opentelemetry/context/Context;

    .line 19
    .line 20
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->get(Lio/opentelemetry/context/Context;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_2
    check-cast p1, Lio/opentelemetry/api/metrics/Meter;

    .line 26
    .line 27
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics;->a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    check-cast p1, Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_4
    check-cast p1, Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->a(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :pswitch_5
    check-cast p1, Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->b(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
