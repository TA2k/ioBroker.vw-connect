.class public final Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final AS_DOUBLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x3a

    .line 2
    .line 3
    const-string v1, "attributes"

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
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x11

    .line 13
    .line 14
    const-string v1, "startTimeUnixNano"

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
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    const/16 v0, 0x19

    .line 24
    .line 25
    const-string v1, "timeUnixNano"

    .line 26
    .line 27
    const/4 v2, 0x3

    .line 28
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x2a

    .line 35
    .line 36
    const-string v1, "exemplars"

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
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    const/16 v0, 0x40

    .line 46
    .line 47
    const-string v1, "flags"

    .line 48
    .line 49
    const/16 v2, 0x8

    .line 50
    .line 51
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 56
    .line 57
    const/16 v0, 0x21

    .line 58
    .line 59
    const-string v1, "asDouble"

    .line 60
    .line 61
    const/4 v2, 0x4

    .line 62
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->AS_DOUBLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 67
    .line 68
    const/16 v0, 0x31

    .line 69
    .line 70
    const-string v1, "asInt"

    .line 71
    .line 72
    const/4 v2, 0x6

    .line 73
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 78
    .line 79
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
