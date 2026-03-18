.class public final enum Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/internal/StandardComponentId;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "ExporterType"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_GRPC_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_GRPC_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_GRPC_PROFILES_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_GRPC_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_HTTP_JSON_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_HTTP_JSON_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_HTTP_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_HTTP_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum OTLP_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum ZIPKIN_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

.field public static final enum ZIPKIN_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;


# instance fields
.field private final signal:Lio/opentelemetry/sdk/internal/Signal;

.field final value:Ljava/lang/String;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
    .locals 12

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 6
    .line 7
    sget-object v3, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 8
    .line 9
    sget-object v4, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 10
    .line 11
    sget-object v5, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 12
    .line 13
    sget-object v6, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 14
    .line 15
    sget-object v7, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 16
    .line 17
    sget-object v8, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 18
    .line 19
    sget-object v9, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->ZIPKIN_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 20
    .line 21
    sget-object v10, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->ZIPKIN_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 22
    .line 23
    sget-object v11, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_PROFILES_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 24
    .line 25
    filled-new-array/range {v0 .. v11}, [Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/internal/Signal;->SPAN:Lio/opentelemetry/sdk/internal/Signal;

    .line 4
    .line 5
    const-string v2, "OTLP_GRPC_SPAN_EXPORTER"

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const-string v4, "otlp_grpc_span_exporter"

    .line 9
    .line 10
    invoke-direct {v0, v2, v3, v4, v1}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 14
    .line 15
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    const-string v3, "otlp_http_span_exporter"

    .line 19
    .line 20
    const-string v4, "OTLP_HTTP_SPAN_EXPORTER"

    .line 21
    .line 22
    invoke-direct {v0, v4, v2, v3, v1}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 26
    .line 27
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 28
    .line 29
    const/4 v2, 0x2

    .line 30
    const-string v3, "otlp_http_json_span_exporter"

    .line 31
    .line 32
    const-string v4, "OTLP_HTTP_JSON_SPAN_EXPORTER"

    .line 33
    .line 34
    invoke-direct {v0, v4, v2, v3, v1}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 35
    .line 36
    .line 37
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 38
    .line 39
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 40
    .line 41
    sget-object v2, Lio/opentelemetry/sdk/internal/Signal;->LOG:Lio/opentelemetry/sdk/internal/Signal;

    .line 42
    .line 43
    const-string v3, "OTLP_GRPC_LOG_EXPORTER"

    .line 44
    .line 45
    const/4 v4, 0x3

    .line 46
    const-string v5, "otlp_grpc_log_exporter"

    .line 47
    .line 48
    invoke-direct {v0, v3, v4, v5, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 49
    .line 50
    .line 51
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 52
    .line 53
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 54
    .line 55
    const/4 v3, 0x4

    .line 56
    const-string v4, "otlp_http_log_exporter"

    .line 57
    .line 58
    const-string v5, "OTLP_HTTP_LOG_EXPORTER"

    .line 59
    .line 60
    invoke-direct {v0, v5, v3, v4, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 64
    .line 65
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 66
    .line 67
    const/4 v3, 0x5

    .line 68
    const-string v4, "otlp_http_json_log_exporter"

    .line 69
    .line 70
    const-string v5, "OTLP_HTTP_JSON_LOG_EXPORTER"

    .line 71
    .line 72
    invoke-direct {v0, v5, v3, v4, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 73
    .line 74
    .line 75
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 76
    .line 77
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 78
    .line 79
    sget-object v2, Lio/opentelemetry/sdk/internal/Signal;->METRIC:Lio/opentelemetry/sdk/internal/Signal;

    .line 80
    .line 81
    const-string v3, "OTLP_GRPC_METRIC_EXPORTER"

    .line 82
    .line 83
    const/4 v4, 0x6

    .line 84
    const-string v5, "otlp_grpc_metric_exporter"

    .line 85
    .line 86
    invoke-direct {v0, v3, v4, v5, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 90
    .line 91
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 92
    .line 93
    const/4 v3, 0x7

    .line 94
    const-string v4, "otlp_http_metric_exporter"

    .line 95
    .line 96
    const-string v5, "OTLP_HTTP_METRIC_EXPORTER"

    .line 97
    .line 98
    invoke-direct {v0, v5, v3, v4, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 99
    .line 100
    .line 101
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 102
    .line 103
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 104
    .line 105
    const/16 v3, 0x8

    .line 106
    .line 107
    const-string v4, "otlp_http_json_metric_exporter"

    .line 108
    .line 109
    const-string v5, "OTLP_HTTP_JSON_METRIC_EXPORTER"

    .line 110
    .line 111
    invoke-direct {v0, v5, v3, v4, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 112
    .line 113
    .line 114
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 115
    .line 116
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 117
    .line 118
    const-string v2, "ZIPKIN_HTTP_SPAN_EXPORTER"

    .line 119
    .line 120
    const/16 v3, 0x9

    .line 121
    .line 122
    const-string v4, "zipkin_http_span_exporter"

    .line 123
    .line 124
    invoke-direct {v0, v2, v3, v4, v1}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 125
    .line 126
    .line 127
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->ZIPKIN_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 128
    .line 129
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 130
    .line 131
    const-string v2, "ZIPKIN_HTTP_JSON_SPAN_EXPORTER"

    .line 132
    .line 133
    const/16 v3, 0xa

    .line 134
    .line 135
    invoke-direct {v0, v2, v3, v4, v1}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 136
    .line 137
    .line 138
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->ZIPKIN_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 139
    .line 140
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 141
    .line 142
    const-string v1, "TBD"

    .line 143
    .line 144
    sget-object v2, Lio/opentelemetry/sdk/internal/Signal;->PROFILE:Lio/opentelemetry/sdk/internal/Signal;

    .line 145
    .line 146
    const-string v3, "OTLP_GRPC_PROFILES_EXPORTER"

    .line 147
    .line 148
    const/16 v4, 0xb

    .line 149
    .line 150
    invoke-direct {v0, v3, v4, v1, v2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;-><init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V

    .line 151
    .line 152
    .line 153
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_PROFILES_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 154
    .line 155
    invoke-static {}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->$values()[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    sput-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->$VALUES:[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 160
    .line 161
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;Lio/opentelemetry/sdk/internal/Signal;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/sdk/internal/Signal;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->value:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p4, p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->$VALUES:[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public signal()Lio/opentelemetry/sdk/internal/Signal;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 2
    .line 3
    return-object p0
.end method
