.class public final Lio/opentelemetry/proto/profiles/v1development/internal/Profile;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ATTRIBUTE_INDICES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final COMMENT_STRINDICES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final DURATION_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final ORIGINAL_PAYLOAD:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final ORIGINAL_PAYLOAD_FORMAT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final PERIOD:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final PERIOD_TYPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final PROFILE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SAMPLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final SAMPLE_TYPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-string v0, "sampleType"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->SAMPLE_TYPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x12

    .line 13
    .line 14
    const-string v1, "sample"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->SAMPLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x20

    .line 35
    .line 36
    const-string v1, "durationNano"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->DURATION_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    const/16 v0, 0x2a

    .line 46
    .line 47
    const-string v1, "periodType"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->PERIOD_TYPE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 55
    .line 56
    const/16 v0, 0x30

    .line 57
    .line 58
    const-string v1, "period"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->PERIOD:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 66
    .line 67
    const/16 v0, 0x3a

    .line 68
    .line 69
    const-string v1, "commentStrindices"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->COMMENT_STRINDICES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 77
    .line 78
    const/16 v0, 0x42

    .line 79
    .line 80
    const-string v1, "profileId"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->PROFILE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 89
    .line 90
    const/16 v0, 0x48

    .line 91
    .line 92
    const-string v1, "droppedAttributesCount"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 101
    .line 102
    const/16 v0, 0x52

    .line 103
    .line 104
    const-string v1, "originalPayloadFormat"

    .line 105
    .line 106
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->ORIGINAL_PAYLOAD_FORMAT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 111
    .line 112
    const/16 v0, 0x5a

    .line 113
    .line 114
    const-string v1, "originalPayload"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->ORIGINAL_PAYLOAD:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 123
    .line 124
    const/16 v0, 0x62

    .line 125
    .line 126
    const-string v1, "attributeIndices"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Profile;->ATTRIBUTE_INDICES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 135
    .line 136
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
