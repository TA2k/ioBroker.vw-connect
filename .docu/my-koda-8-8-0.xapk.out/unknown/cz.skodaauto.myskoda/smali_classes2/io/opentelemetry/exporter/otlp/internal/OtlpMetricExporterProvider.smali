.class public Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/autoconfigure/spi/metrics/ConfigurableMetricExporterProvider;
.implements Lio/opentelemetry/sdk/autoconfigure/spi/internal/AutoConfigureListener;


# instance fields
.field private final meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public afterAutoConfigure(Lio/opentelemetry/sdk/OpenTelemetrySdk;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/sdk/OpenTelemetrySdk;->getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public createExporter(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;)Lio/opentelemetry/sdk/metrics/export/MetricExporter;
    .locals 13

    .line 1
    const-string v1, "metrics"

    .line 2
    .line 3
    invoke-static {v1, p1}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->getOtlpProtocol(Ljava/lang/String;Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v3, "http/protobuf"

    .line 8
    .line 9
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    if-eqz v3, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;->httpBuilder()Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v12

    .line 19
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    new-instance v3, Lex0/j;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {v3, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 26
    .line 27
    .line 28
    new-instance v4, Lex0/j;

    .line 29
    .line 30
    const/4 v1, 0x3

    .line 31
    invoke-direct {v4, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 32
    .line 33
    .line 34
    new-instance v5, Lex0/k;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-direct {v5, v12, v1}, Lex0/k;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 38
    .line 39
    .line 40
    new-instance v6, Lex0/j;

    .line 41
    .line 42
    const/4 v1, 0x4

    .line 43
    invoke-direct {v6, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 44
    .line 45
    .line 46
    new-instance v7, Lex0/j;

    .line 47
    .line 48
    const/4 v1, 0x5

    .line 49
    invoke-direct {v7, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 50
    .line 51
    .line 52
    new-instance v8, Lex0/j;

    .line 53
    .line 54
    const/4 v1, 0x6

    .line 55
    invoke-direct {v8, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 56
    .line 57
    .line 58
    new-instance v9, Lex0/k;

    .line 59
    .line 60
    const/4 v1, 0x1

    .line 61
    invoke-direct {v9, v12, v1}, Lex0/k;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 62
    .line 63
    .line 64
    new-instance v10, Lex0/j;

    .line 65
    .line 66
    const/4 v1, 0x7

    .line 67
    invoke-direct {v10, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 68
    .line 69
    .line 70
    new-instance v11, Lex0/j;

    .line 71
    .line 72
    const/16 v1, 0x8

    .line 73
    .line 74
    invoke-direct {v11, v12, v1}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 75
    .line 76
    .line 77
    const-string v1, "metrics"

    .line 78
    .line 79
    move-object v2, p1

    .line 80
    invoke-static/range {v1 .. v11}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->configureOtlpExporterBuilder(Ljava/lang/String;Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 81
    .line 82
    .line 83
    new-instance v1, Lex0/j;

    .line 84
    .line 85
    const/4 v3, 0x1

    .line 86
    invoke-direct {v1, v12, v3}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 87
    .line 88
    .line 89
    invoke-static {p1, v1}, Lio/opentelemetry/exporter/internal/ExporterBuilderUtil;->configureOtlpAggregationTemporality(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;)V

    .line 90
    .line 91
    .line 92
    new-instance v1, Lex0/j;

    .line 93
    .line 94
    const/4 v3, 0x2

    .line 95
    invoke-direct {v1, v12, v3}, Lex0/j;-><init>(Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;I)V

    .line 96
    .line 97
    .line 98
    invoke-static {p1, v1}, Lio/opentelemetry/exporter/internal/ExporterBuilderUtil;->configureOtlpHistogramDefaultAggregation(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;)V

    .line 99
    .line 100
    .line 101
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 102
    .line 103
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    new-instance v1, Lex0/n;

    .line 107
    .line 108
    const/4 v2, 0x0

    .line 109
    invoke-direct {v1, v0, v2}, Lex0/n;-><init>(Ljava/lang/Object;I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v12, v1}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v12}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporter;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    return-object v0

    .line 120
    :cond_0
    const-string v3, "grpc"

    .line 121
    .line 122
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-eqz v3, :cond_1

    .line 127
    .line 128
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;->grpcBuilder()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;

    .line 129
    .line 130
    .line 131
    move-result-object v12

    .line 132
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    new-instance v3, Lex0/d;

    .line 136
    .line 137
    const/4 v1, 0x0

    .line 138
    invoke-direct {v3, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 139
    .line 140
    .line 141
    new-instance v4, Lex0/d;

    .line 142
    .line 143
    const/4 v1, 0x3

    .line 144
    invoke-direct {v4, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 145
    .line 146
    .line 147
    new-instance v5, Lex0/e;

    .line 148
    .line 149
    const/4 v1, 0x0

    .line 150
    invoke-direct {v5, v12, v1}, Lex0/e;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 151
    .line 152
    .line 153
    new-instance v6, Lex0/d;

    .line 154
    .line 155
    const/4 v1, 0x4

    .line 156
    invoke-direct {v6, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 157
    .line 158
    .line 159
    new-instance v7, Lex0/d;

    .line 160
    .line 161
    const/4 v1, 0x5

    .line 162
    invoke-direct {v7, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 163
    .line 164
    .line 165
    new-instance v8, Lex0/d;

    .line 166
    .line 167
    const/4 v1, 0x6

    .line 168
    invoke-direct {v8, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 169
    .line 170
    .line 171
    new-instance v9, Lex0/e;

    .line 172
    .line 173
    const/4 v1, 0x1

    .line 174
    invoke-direct {v9, v12, v1}, Lex0/e;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 175
    .line 176
    .line 177
    new-instance v10, Lex0/d;

    .line 178
    .line 179
    const/4 v1, 0x7

    .line 180
    invoke-direct {v10, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 181
    .line 182
    .line 183
    new-instance v11, Lex0/d;

    .line 184
    .line 185
    const/16 v1, 0x8

    .line 186
    .line 187
    invoke-direct {v11, v12, v1}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 188
    .line 189
    .line 190
    const-string v1, "metrics"

    .line 191
    .line 192
    move-object v2, p1

    .line 193
    invoke-static/range {v1 .. v11}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->configureOtlpExporterBuilder(Ljava/lang/String;Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 194
    .line 195
    .line 196
    new-instance v1, Lex0/d;

    .line 197
    .line 198
    const/4 v3, 0x1

    .line 199
    invoke-direct {v1, v12, v3}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 200
    .line 201
    .line 202
    invoke-static {p1, v1}, Lio/opentelemetry/exporter/internal/ExporterBuilderUtil;->configureOtlpAggregationTemporality(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;)V

    .line 203
    .line 204
    .line 205
    new-instance v1, Lex0/d;

    .line 206
    .line 207
    const/4 v3, 0x2

    .line 208
    invoke-direct {v1, v12, v3}, Lex0/d;-><init>(Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;I)V

    .line 209
    .line 210
    .line 211
    invoke-static {p1, v1}, Lio/opentelemetry/exporter/internal/ExporterBuilderUtil;->configureOtlpHistogramDefaultAggregation(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;)V

    .line 212
    .line 213
    .line 214
    iget-object v0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpMetricExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 215
    .line 216
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    new-instance v1, Lex0/n;

    .line 220
    .line 221
    const/4 v2, 0x0

    .line 222
    invoke-direct {v1, v0, v2}, Lex0/n;-><init>(Ljava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v12, v1}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;

    .line 226
    .line 227
    .line 228
    invoke-virtual {v12}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    return-object v0

    .line 233
    :cond_1
    new-instance v0, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;

    .line 234
    .line 235
    const-string v2, "Unsupported OTLP metrics protocol: "

    .line 236
    .line 237
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;-><init>(Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    throw v0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "otlp"

    .line 2
    .line 3
    return-object p0
.end method

.method public grpcBuilder()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->builder()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public httpBuilder()Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporter;->builder()Lio/opentelemetry/exporter/otlp/http/metrics/OtlpHttpMetricExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
