.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final CLIENT_OPERATION_DURATION_BUCKETS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field static final CLIENT_TOKEN_USAGE_BUCKETS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    const-wide v0, 0x3f847ae147ae147bL    # 0.01

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    const-wide v0, 0x3f947ae147ae147bL    # 0.02

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    const-wide v0, 0x3fa47ae147ae147bL    # 0.04

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    const-wide v0, 0x3fb47ae147ae147bL    # 0.08

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    const-wide v0, 0x3fc47ae147ae147bL    # 0.16

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 43
    .line 44
    .line 45
    move-result-object v6

    .line 46
    const-wide v0, 0x3fd47ae147ae147bL    # 0.32

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    const-wide v0, 0x3fe47ae147ae147bL    # 0.64

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 61
    .line 62
    .line 63
    move-result-object v8

    .line 64
    const-wide v0, 0x3ff47ae147ae147bL    # 1.28

    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 70
    .line 71
    .line 72
    move-result-object v9

    .line 73
    const-wide v0, 0x40047ae147ae147bL    # 2.56

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 79
    .line 80
    .line 81
    move-result-object v10

    .line 82
    const-wide v0, 0x40147ae147ae147bL    # 5.12

    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 88
    .line 89
    .line 90
    move-result-object v11

    .line 91
    const-wide v0, 0x40247ae147ae147bL    # 10.24

    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 97
    .line 98
    .line 99
    move-result-object v12

    .line 100
    const-wide v0, 0x40347ae147ae147bL    # 20.48

    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 106
    .line 107
    .line 108
    move-result-object v13

    .line 109
    const-wide v0, 0x40447ae147ae147bL    # 40.96

    .line 110
    .line 111
    .line 112
    .line 113
    .line 114
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 115
    .line 116
    .line 117
    move-result-object v14

    .line 118
    const-wide v0, 0x40547ae147ae147bL    # 81.92

    .line 119
    .line 120
    .line 121
    .line 122
    .line 123
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 124
    .line 125
    .line 126
    move-result-object v15

    .line 127
    filled-new-array/range {v2 .. v15}, [Ljava/lang/Double;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;->CLIENT_OPERATION_DURATION_BUCKETS:Ljava/util/List;

    .line 140
    .line 141
    const-wide/16 v0, 0x1

    .line 142
    .line 143
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    const-wide/16 v0, 0x4

    .line 148
    .line 149
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    const-wide/16 v0, 0x10

    .line 154
    .line 155
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    const-wide/16 v0, 0x40

    .line 160
    .line 161
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 162
    .line 163
    .line 164
    move-result-object v5

    .line 165
    const-wide/16 v0, 0x100

    .line 166
    .line 167
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 168
    .line 169
    .line 170
    move-result-object v6

    .line 171
    const-wide/16 v0, 0x400

    .line 172
    .line 173
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 174
    .line 175
    .line 176
    move-result-object v7

    .line 177
    const-wide/16 v0, 0x1000

    .line 178
    .line 179
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 180
    .line 181
    .line 182
    move-result-object v8

    .line 183
    const-wide/16 v0, 0x4000

    .line 184
    .line 185
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 186
    .line 187
    .line 188
    move-result-object v9

    .line 189
    const-wide/32 v0, 0x10000

    .line 190
    .line 191
    .line 192
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 193
    .line 194
    .line 195
    move-result-object v10

    .line 196
    const-wide/32 v0, 0x40000

    .line 197
    .line 198
    .line 199
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 200
    .line 201
    .line 202
    move-result-object v11

    .line 203
    const-wide/32 v0, 0x100000

    .line 204
    .line 205
    .line 206
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 207
    .line 208
    .line 209
    move-result-object v12

    .line 210
    const-wide/32 v0, 0x400000

    .line 211
    .line 212
    .line 213
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 214
    .line 215
    .line 216
    move-result-object v13

    .line 217
    const-wide/32 v0, 0x1000000

    .line 218
    .line 219
    .line 220
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 221
    .line 222
    .line 223
    move-result-object v14

    .line 224
    const-wide/32 v0, 0x4000000

    .line 225
    .line 226
    .line 227
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 228
    .line 229
    .line 230
    move-result-object v15

    .line 231
    filled-new-array/range {v2 .. v15}, [Ljava/lang/Long;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;->CLIENT_TOKEN_USAGE_BUCKETS:Ljava/util/List;

    .line 244
    .line 245
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static applyClientOperationDurationAdvice(Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 7
    .line 8
    const/4 v0, 0x7

    .line 9
    new-array v0, v0, [Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    aput-object v1, v0, v2

    .line 15
    .line 16
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_PROVIDER_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    aput-object v1, v0, v2

    .line 20
    .line 21
    sget-object v1, Lio/opentelemetry/semconv/ErrorAttributes;->ERROR_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    aput-object v1, v0, v2

    .line 25
    .line 26
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    aput-object v1, v0, v2

    .line 30
    .line 31
    sget-object v1, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    aput-object v1, v0, v2

    .line 35
    .line 36
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    aput-object v1, v0, v2

    .line 40
    .line 41
    sget-object v1, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 42
    .line 43
    const/4 v2, 0x6

    .line 44
    aput-object v1, v0, v2

    .line 45
    .line 46
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public static applyClientTokenUsageAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V
    .locals 3

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 7
    .line 8
    const/4 v0, 0x7

    .line 9
    new-array v0, v0, [Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    aput-object v1, v0, v2

    .line 15
    .line 16
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_PROVIDER_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    aput-object v1, v0, v2

    .line 20
    .line 21
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_TOKEN_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    aput-object v1, v0, v2

    .line 25
    .line 26
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    aput-object v1, v0, v2

    .line 30
    .line 31
    sget-object v1, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    aput-object v1, v0, v2

    .line 35
    .line 36
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 37
    .line 38
    const/4 v2, 0x5

    .line 39
    aput-object v1, v0, v2

    .line 40
    .line 41
    sget-object v1, Lio/opentelemetry/semconv/ServerAttributes;->SERVER_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 42
    .line 43
    const/4 v2, 0x6

    .line 44
    aput-object v1, v0, v2

    .line 45
    .line 46
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;->setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    .line 51
    .line 52
    .line 53
    return-void
.end method
