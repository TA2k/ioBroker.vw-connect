.class public final Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;
    }
.end annotation


# static fields
.field public static final ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final NEGATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final POSITIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SCALE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final ZERO_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final ZERO_THRESHOLD:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-string v0, "attributes"

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/16 v2, 0xa

    .line 5
    .line 6
    invoke-static {v1, v2, v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x11

    .line 13
    .line 14
    const-string v1, "startTimeUnixNano"

    .line 15
    .line 16
    const/4 v3, 0x2

    .line 17
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    const/16 v0, 0x19

    .line 24
    .line 25
    const-string v1, "timeUnixNano"

    .line 26
    .line 27
    const/4 v3, 0x3

    .line 28
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x21

    .line 35
    .line 36
    const-string v1, "count"

    .line 37
    .line 38
    const/4 v3, 0x4

    .line 39
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    const/16 v0, 0x29

    .line 46
    .line 47
    const-string v1, "sum"

    .line 48
    .line 49
    const/4 v3, 0x5

    .line 50
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 55
    .line 56
    const/16 v0, 0x30

    .line 57
    .line 58
    const-string v1, "scale"

    .line 59
    .line 60
    const/4 v3, 0x6

    .line 61
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SCALE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 66
    .line 67
    const/16 v0, 0x39

    .line 68
    .line 69
    const-string v1, "zeroCount"

    .line 70
    .line 71
    const/4 v3, 0x7

    .line 72
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ZERO_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 77
    .line 78
    const/16 v0, 0x42

    .line 79
    .line 80
    const-string v1, "positive"

    .line 81
    .line 82
    const/16 v3, 0x8

    .line 83
    .line 84
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->POSITIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 89
    .line 90
    const/16 v0, 0x4a

    .line 91
    .line 92
    const-string v1, "negative"

    .line 93
    .line 94
    const/16 v3, 0x9

    .line 95
    .line 96
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->NEGATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 101
    .line 102
    const/16 v0, 0x50

    .line 103
    .line 104
    const-string v1, "flags"

    .line 105
    .line 106
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 111
    .line 112
    const/16 v0, 0x5a

    .line 113
    .line 114
    const-string v1, "exemplars"

    .line 115
    .line 116
    const/16 v2, 0xb

    .line 117
    .line 118
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 123
    .line 124
    const/16 v0, 0x61

    .line 125
    .line 126
    const-string v1, "min"

    .line 127
    .line 128
    const/16 v2, 0xc

    .line 129
    .line 130
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 135
    .line 136
    const/16 v0, 0x69

    .line 137
    .line 138
    const-string v1, "max"

    .line 139
    .line 140
    const/16 v2, 0xd

    .line 141
    .line 142
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 147
    .line 148
    const/16 v0, 0x71

    .line 149
    .line 150
    const-string v1, "zeroThreshold"

    .line 151
    .line 152
    const/16 v2, 0xe

    .line 153
    .line 154
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ZERO_THRESHOLD:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 159
    .line 160
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
