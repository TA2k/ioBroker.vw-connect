.class public final synthetic Lio/opentelemetry/api/logs/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/api/logs/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/api/logs/a;->b:Ljava/lang/Object;

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
    iget v0, p0, Lio/opentelemetry/api/logs/a;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/api/logs/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Llk/c;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Llk/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p0, La50/d;

    .line 15
    .line 16
    invoke-virtual {p0, p1, p2}, La50/d;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_1
    check-cast p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 21
    .line 22
    check-cast p1, Lio/opentelemetry/api/common/Attributes;

    .line 23
    .line 24
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 25
    .line 26
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->a(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_2
    check-cast p0, Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;

    .line 31
    .line 32
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 33
    .line 34
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;->a(Lio/opentelemetry/sdk/logs/internal/ExtendedReadWriteLogRecord;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :pswitch_3
    check-cast p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 39
    .line 40
    check-cast p1, Ljava/lang/String;

    .line 41
    .line 42
    check-cast p2, Ljava/lang/String;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->addConstantHeader(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :pswitch_4
    check-cast p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 49
    .line 50
    check-cast p1, Ljava/lang/String;

    .line 51
    .line 52
    check-cast p2, Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->addConstantHeaders(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :pswitch_5
    check-cast p0, Ljava/util/ArrayList;

    .line 59
    .line 60
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 61
    .line 62
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;->a(Ljava/util/ArrayList;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :pswitch_6
    check-cast p0, Lio/opentelemetry/api/trace/SpanBuilder;

    .line 67
    .line 68
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 69
    .line 70
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/trace/SpanBuilder;->a(Lio/opentelemetry/api/trace/SpanBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :pswitch_7
    check-cast p0, Lio/opentelemetry/api/trace/Span;

    .line 75
    .line 76
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 77
    .line 78
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/trace/Span;->a(Lio/opentelemetry/api/trace/Span;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :pswitch_8
    check-cast p0, Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 83
    .line 84
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 85
    .line 86
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/logs/LogRecordBuilder;->c(Lio/opentelemetry/api/logs/LogRecordBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
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
