.class public final synthetic Lex0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lex0/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lex0/a;->b:Ljava/lang/Object;

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
    iget v0, p0, Lex0/a;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lex0/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/util/ArrayList;

    .line 9
    .line 10
    check-cast p1, Ly01/b;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    check-cast p0, Ljava/io/PrintWriter;

    .line 17
    .line 18
    check-cast p1, Ljava/util/Map$Entry;

    .line 19
    .line 20
    invoke-static {p0, p1}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketHandshake;->a(Ljava/io/PrintWriter;Ljava/util/Map$Entry;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_1
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 25
    .line 26
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->returnObject(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_2
    check-cast p0, [Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 33
    .line 34
    check-cast p1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;

    .line 35
    .line 36
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->a([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :pswitch_3
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 41
    .line 42
    check-cast p1, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 43
    .line 44
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->b(Ljava/util/LinkedHashMap;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :pswitch_4
    check-cast p0, Ljava/util/function/BiConsumer;

    .line 49
    .line 50
    check-cast p1, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 51
    .line 52
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/otlp/internal/OtlpDeclarativeConfigUtil;->a(Ljava/util/function/BiConsumer;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
