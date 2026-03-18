.class public final synthetic Lio/opentelemetry/exporter/internal/grpc/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Supplier;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/exporter/internal/grpc/b;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/grpc/b;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lio/opentelemetry/sdk/logs/LogLimits;->getDefault()Lio/opentelemetry/sdk/logs/LogLimits;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/LogLimits;->toBuilder()Lio/opentelemetry/sdk/logs/LogLimitsBuilder;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/16 v0, 0xfff

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->setMaxAttributeValueLength(I)Lio/opentelemetry/sdk/logs/LogLimitsBuilder;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/LogLimitsBuilder;->build()Lio/opentelemetry/sdk/logs/LogLimits;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    invoke-static {}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->b()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_1
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_2
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->a()Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_3
    invoke-static {}, Lio/opentelemetry/sdk/logs/LogLimits;->getDefault()Lio/opentelemetry/sdk/logs/LogLimits;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :pswitch_4
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_5
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 52
    .line 53
    return-object p0

    .line 54
    nop

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
