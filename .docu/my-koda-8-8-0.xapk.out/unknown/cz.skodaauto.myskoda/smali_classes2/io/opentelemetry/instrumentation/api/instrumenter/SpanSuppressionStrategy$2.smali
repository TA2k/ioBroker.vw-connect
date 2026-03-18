.class final enum Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$2;
.super Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4011
    name = null
.end annotation


# instance fields
.field private final strategy:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;


# direct methods
.method public constructor <init>(Ljava/lang/String;I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;-><init>(Ljava/lang/String;ILio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$1;)V

    .line 3
    .line 4
    .line 5
    new-instance p1, Ljava/util/EnumMap;

    .line 6
    .line 7
    const-class p2, Lio/opentelemetry/api/trace/SpanKind;

    .line 8
    .line 9
    invoke-direct {p1, p2}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    .line 10
    .line 11
    .line 12
    sget-object p2, Lio/opentelemetry/api/trace/SpanKind;->SERVER:Lio/opentelemetry/api/trace/SpanKind;

    .line 13
    .line 14
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;

    .line 15
    .line 16
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->KIND_SERVER:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 17
    .line 18
    invoke-static {v1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;-><init>(Ljava/util/Set;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, p2, v0}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    sget-object p2, Lio/opentelemetry/api/trace/SpanKind;->CLIENT:Lio/opentelemetry/api/trace/SpanKind;

    .line 29
    .line 30
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;

    .line 31
    .line 32
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->KIND_CLIENT:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 33
    .line 34
    invoke-static {v1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;-><init>(Ljava/util/Set;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1, p2, v0}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    sget-object p2, Lio/opentelemetry/api/trace/SpanKind;->CONSUMER:Lio/opentelemetry/api/trace/SpanKind;

    .line 45
    .line 46
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;

    .line 47
    .line 48
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->KIND_CONSUMER:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 49
    .line 50
    invoke-static {v1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;-><init>(Ljava/util/Set;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, p2, v0}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    sget-object p2, Lio/opentelemetry/api/trace/SpanKind;->PRODUCER:Lio/opentelemetry/api/trace/SpanKind;

    .line 61
    .line 62
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;

    .line 63
    .line 64
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->KIND_PRODUCER:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 65
    .line 66
    invoke-static {v1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$BySpanKey;-><init>(Ljava/util/Set;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, p2, v0}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    new-instance p2, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$DelegateBySpanKind;

    .line 77
    .line 78
    invoke-direct {p2, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$DelegateBySpanKind;-><init>(Ljava/util/Map;)V

    .line 79
    .line 80
    .line 81
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$2;->strategy:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 82
    .line 83
    return-void
.end method


# virtual methods
.method public create(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lio/opentelemetry/instrumentation/api/internal/SpanKey;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$2;->strategy:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 2
    .line 3
    return-object p0
.end method
