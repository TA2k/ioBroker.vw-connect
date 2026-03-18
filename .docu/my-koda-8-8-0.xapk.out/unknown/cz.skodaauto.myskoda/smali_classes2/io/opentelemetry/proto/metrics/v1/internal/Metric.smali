.class public final Lio/opentelemetry/proto/metrics/v1/internal/Metric;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final DESCRIPTION:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final EXPONENTIAL_HISTOGRAM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final GAUGE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final HISTOGRAM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final METADATA:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SUMMARY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final UNIT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-string v0, "name"

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
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x12

    .line 13
    .line 14
    const-string v1, "description"

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
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->DESCRIPTION:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    const/16 v0, 0x1a

    .line 24
    .line 25
    const-string v1, "unit"

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
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->UNIT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x62

    .line 35
    .line 36
    const-string v1, "metadata"

    .line 37
    .line 38
    const/16 v3, 0xc

    .line 39
    .line 40
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->METADATA:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 45
    .line 46
    const/16 v0, 0x2a

    .line 47
    .line 48
    const-string v1, "gauge"

    .line 49
    .line 50
    const/4 v3, 0x5

    .line 51
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->GAUGE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 56
    .line 57
    const/16 v0, 0x3a

    .line 58
    .line 59
    const-string v1, "sum"

    .line 60
    .line 61
    const/4 v3, 0x7

    .line 62
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 67
    .line 68
    const/16 v0, 0x4a

    .line 69
    .line 70
    const-string v1, "histogram"

    .line 71
    .line 72
    const/16 v3, 0x9

    .line 73
    .line 74
    invoke-static {v3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->HISTOGRAM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 79
    .line 80
    const/16 v0, 0x52

    .line 81
    .line 82
    const-string v1, "exponentialHistogram"

    .line 83
    .line 84
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->EXPONENTIAL_HISTOGRAM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 89
    .line 90
    const/16 v0, 0x5a

    .line 91
    .line 92
    const-string v1, "summary"

    .line 93
    .line 94
    const/16 v2, 0xb

    .line 95
    .line 96
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    sput-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->SUMMARY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 101
    .line 102
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
