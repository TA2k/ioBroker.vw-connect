.class public final synthetic Lfx0/e;
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
    iput p2, p0, Lfx0/e;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lfx0/e;->b:Ljava/lang/Object;

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
    iget v0, p0, Lfx0/e;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lfx0/e;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt51/c;

    .line 9
    .line 10
    invoke-static {p0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->h(Lt51/c;Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p0, Lt40/a;

    .line 16
    .line 17
    invoke-static {p0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->e(Lt40/a;Ljava/lang/Object;)Ljava/util/Optional;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    check-cast p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 23
    .line 24
    check-cast p1, Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {p0, p1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;->a(Lio/opentelemetry/semconv/AttributeKeyTemplate;Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_2
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;

    .line 32
    .line 33
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 34
    .line 35
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;->a(Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;)Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_3
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 41
    .line 42
    check-cast p1, Lio/opentelemetry/api/common/Attributes;

    .line 43
    .line 44
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->e(Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_4
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;

    .line 50
    .line 51
    check-cast p1, Ljava/lang/String;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_5
    check-cast p0, Ljava/lang/String;

    .line 59
    .line 60
    check-cast p1, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 61
    .line 62
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->f(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_6
    check-cast p0, Ljava/util/function/Function;

    .line 68
    .line 69
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->a(Ljava/util/function/Function;Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_7
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalAttributesGetter;

    .line 75
    .line 76
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalAttributesGetter;->getUrlTemplate(Ljava/lang/Object;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
