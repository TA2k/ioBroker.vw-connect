.class public final Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final EXPLICIT_BOUNDS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x4a

    .line 2
    .line 3
    const-string v1, "attributes"

    .line 4
    .line 5
    const/16 v2, 0x9

    .line 6
    .line 7
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 12
    .line 13
    const/16 v0, 0x11

    .line 14
    .line 15
    const-string v1, "startTimeUnixNano"

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    const/16 v0, 0x19

    .line 25
    .line 26
    const-string v1, "timeUnixNano"

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 34
    .line 35
    const/16 v0, 0x21

    .line 36
    .line 37
    const-string v1, "count"

    .line 38
    .line 39
    const/4 v2, 0x4

    .line 40
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 45
    .line 46
    const/16 v0, 0x29

    .line 47
    .line 48
    const-string v1, "sum"

    .line 49
    .line 50
    const/4 v2, 0x5

    .line 51
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 56
    .line 57
    const/16 v0, 0x32

    .line 58
    .line 59
    const-string v1, "bucketCounts"

    .line 60
    .line 61
    const/4 v2, 0x6

    .line 62
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 67
    .line 68
    const/16 v0, 0x3a

    .line 69
    .line 70
    const-string v1, "explicitBounds"

    .line 71
    .line 72
    const/4 v2, 0x7

    .line 73
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->EXPLICIT_BOUNDS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 78
    .line 79
    const/16 v0, 0x42

    .line 80
    .line 81
    const-string v1, "exemplars"

    .line 82
    .line 83
    const/16 v2, 0x8

    .line 84
    .line 85
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 90
    .line 91
    const/16 v0, 0x50

    .line 92
    .line 93
    const-string v1, "flags"

    .line 94
    .line 95
    const/16 v2, 0xa

    .line 96
    .line 97
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 102
    .line 103
    const/16 v0, 0x59

    .line 104
    .line 105
    const-string v1, "min"

    .line 106
    .line 107
    const/16 v2, 0xb

    .line 108
    .line 109
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 114
    .line 115
    const/16 v0, 0x61

    .line 116
    .line 117
    const-string v1, "max"

    .line 118
    .line 119
    const/16 v2, 0xc

    .line 120
    .line 121
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 126
    .line 127
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
