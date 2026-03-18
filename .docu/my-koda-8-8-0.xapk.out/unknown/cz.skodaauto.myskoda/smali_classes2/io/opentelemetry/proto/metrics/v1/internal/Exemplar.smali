.class public final Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final AS_DOUBLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final FILTERED_ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x3a

    .line 2
    .line 3
    const-string v1, "filteredAttributes"

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->FILTERED_ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x11

    .line 13
    .line 14
    const-string v1, "timeUnixNano"

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    const/16 v0, 0x22

    .line 24
    .line 25
    const-string v1, "spanId"

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x2a

    .line 35
    .line 36
    const-string v1, "traceId"

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    const/16 v0, 0x19

    .line 46
    .line 47
    const-string v1, "asDouble"

    .line 48
    .line 49
    const/4 v2, 0x3

    .line 50
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->AS_DOUBLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 55
    .line 56
    const/16 v0, 0x31

    .line 57
    .line 58
    const-string v1, "asInt"

    .line 59
    .line 60
    const/4 v2, 0x6

    .line 61
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 66
    .line 67
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
