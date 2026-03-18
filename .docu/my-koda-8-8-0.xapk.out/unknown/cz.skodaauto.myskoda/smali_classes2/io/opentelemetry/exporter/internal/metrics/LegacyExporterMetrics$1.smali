.class synthetic Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1009
    name = null
.end annotation


# static fields
.field static final synthetic $SwitchMap$io$opentelemetry$sdk$internal$Signal:[I

.field static final synthetic $SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/internal/Signal;->values()[Lio/opentelemetry/sdk/internal/Signal;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    sput-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$Signal:[I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    :try_start_0
    sget-object v2, Lio/opentelemetry/sdk/internal/Signal;->SPAN:Lio/opentelemetry/sdk/internal/Signal;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    :catch_0
    const/4 v0, 0x2

    .line 20
    :try_start_1
    sget-object v2, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$Signal:[I

    .line 21
    .line 22
    sget-object v3, Lio/opentelemetry/sdk/internal/Signal;->LOG:Lio/opentelemetry/sdk/internal/Signal;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    aput v0, v2, v3
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 29
    .line 30
    :catch_1
    const/4 v2, 0x3

    .line 31
    :try_start_2
    sget-object v3, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$Signal:[I

    .line 32
    .line 33
    sget-object v4, Lio/opentelemetry/sdk/internal/Signal;->METRIC:Lio/opentelemetry/sdk/internal/Signal;

    .line 34
    .line 35
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    aput v2, v3, v4
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 40
    .line 41
    :catch_2
    const/4 v3, 0x4

    .line 42
    :try_start_3
    sget-object v4, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$Signal:[I

    .line 43
    .line 44
    sget-object v5, Lio/opentelemetry/sdk/internal/Signal;->PROFILE:Lio/opentelemetry/sdk/internal/Signal;

    .line 45
    .line 46
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    aput v3, v4, v5
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 51
    .line 52
    :catch_3
    invoke-static {}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->values()[Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    array-length v4, v4

    .line 57
    new-array v4, v4, [I

    .line 58
    .line 59
    sput-object v4, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 60
    .line 61
    :try_start_4
    sget-object v5, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 62
    .line 63
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    aput v1, v4, v5
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 68
    .line 69
    :catch_4
    :try_start_5
    sget-object v1, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 70
    .line 71
    sget-object v4, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 72
    .line 73
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    aput v0, v1, v4
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 78
    .line 79
    :catch_5
    :try_start_6
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 80
    .line 81
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 82
    .line 83
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    aput v2, v0, v1
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 88
    .line 89
    :catch_6
    :try_start_7
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 90
    .line 91
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->ZIPKIN_HTTP_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 92
    .line 93
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    aput v3, v0, v1
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 98
    .line 99
    :catch_7
    :try_start_8
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 100
    .line 101
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->ZIPKIN_HTTP_JSON_SPAN_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    const/4 v2, 0x5

    .line 108
    aput v2, v0, v1
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 109
    .line 110
    :catch_8
    :try_start_9
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 111
    .line 112
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 113
    .line 114
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 115
    .line 116
    .line 117
    move-result v1

    .line 118
    const/4 v2, 0x6

    .line 119
    aput v2, v0, v1
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 120
    .line 121
    :catch_9
    :try_start_a
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 122
    .line 123
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 124
    .line 125
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    const/4 v2, 0x7

    .line 130
    aput v2, v0, v1
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 131
    .line 132
    :catch_a
    :try_start_b
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 133
    .line 134
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_LOG_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 135
    .line 136
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    const/16 v2, 0x8

    .line 141
    .line 142
    aput v2, v0, v1
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 143
    .line 144
    :catch_b
    :try_start_c
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 145
    .line 146
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 147
    .line 148
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    const/16 v2, 0x9

    .line 153
    .line 154
    aput v2, v0, v1
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 155
    .line 156
    :catch_c
    :try_start_d
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 157
    .line 158
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 159
    .line 160
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    const/16 v2, 0xa

    .line 165
    .line 166
    aput v2, v0, v1
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 167
    .line 168
    :catch_d
    :try_start_e
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 169
    .line 170
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_HTTP_JSON_METRIC_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 171
    .line 172
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    const/16 v2, 0xb

    .line 177
    .line 178
    aput v2, v0, v1
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 179
    .line 180
    :catch_e
    :try_start_f
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 181
    .line 182
    sget-object v1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->OTLP_GRPC_PROFILES_EXPORTER:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 183
    .line 184
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    const/16 v2, 0xc

    .line 189
    .line 190
    aput v2, v0, v1
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 191
    .line 192
    :catch_f
    return-void
.end method
