.class public final synthetic Lfx0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Supplier;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfx0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfx0/c;->e:Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lfx0/c;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lfx0/c;->e:Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->shouldEmitExperimentalHttpServerTelemetry()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getServerResponseHeaders()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getServerRequestHeaders()Ljava/util/List;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_2
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getPeerServiceResolver()Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getClientResponseHeaders()Ljava/util/List;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_4
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getClientRequestHeaders()Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :pswitch_5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->redactQueryParameters()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    goto :goto_0

    .line 47
    :pswitch_6
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getKnownHttpRequestMethods()Ljava/util/Set;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :pswitch_7
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->shouldEmitExperimentalHttpClientTelemetry()Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    goto :goto_0

    .line 57
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
