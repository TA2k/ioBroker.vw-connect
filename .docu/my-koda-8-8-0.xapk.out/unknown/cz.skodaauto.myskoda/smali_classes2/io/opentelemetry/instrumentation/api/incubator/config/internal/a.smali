.class public final synthetic Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->httpServerResponseCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->httpServerRequestCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_1
    invoke-static {p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->httpClientResponseCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_2
    invoke-static {p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->httpClientRequestCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :pswitch_3
    invoke-static {p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->peerServiceMapping(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/Map;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
