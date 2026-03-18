.class public Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/autoconfigure/spi/logs/ConfigurableLogRecordExporterProvider;
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
    iput-object v0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public afterAutoConfigure(Lio/opentelemetry/sdk/OpenTelemetrySdk;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

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

.method public createExporter(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;)Lio/opentelemetry/sdk/logs/export/LogRecordExporter;
    .locals 12

    .line 1
    const-string v0, "logs"

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->getOtlpProtocol(Ljava/lang/String;Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "http/protobuf"

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;->httpBuilder()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    new-instance v3, Lex0/h;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {v3, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 26
    .line 27
    .line 28
    new-instance v4, Lex0/h;

    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    invoke-direct {v4, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 32
    .line 33
    .line 34
    new-instance v5, Lex0/i;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-direct {v5, v0, v1}, Lex0/i;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 38
    .line 39
    .line 40
    new-instance v6, Lex0/h;

    .line 41
    .line 42
    const/4 v1, 0x2

    .line 43
    invoke-direct {v6, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 44
    .line 45
    .line 46
    new-instance v7, Lex0/h;

    .line 47
    .line 48
    const/4 v1, 0x3

    .line 49
    invoke-direct {v7, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 50
    .line 51
    .line 52
    new-instance v8, Lex0/h;

    .line 53
    .line 54
    const/4 v1, 0x4

    .line 55
    invoke-direct {v8, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 56
    .line 57
    .line 58
    new-instance v9, Lex0/i;

    .line 59
    .line 60
    const/4 v1, 0x1

    .line 61
    invoke-direct {v9, v0, v1}, Lex0/i;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 62
    .line 63
    .line 64
    new-instance v10, Lex0/h;

    .line 65
    .line 66
    const/4 v1, 0x5

    .line 67
    invoke-direct {v10, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 68
    .line 69
    .line 70
    new-instance v11, Lex0/h;

    .line 71
    .line 72
    const/4 v1, 0x6

    .line 73
    invoke-direct {v11, v0, v1}, Lex0/h;-><init>(Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;I)V

    .line 74
    .line 75
    .line 76
    const-string v1, "logs"

    .line 77
    .line 78
    move-object v2, p1

    .line 79
    invoke-static/range {v1 .. v11}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->configureOtlpExporterBuilder(Ljava/lang/String;Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 83
    .line 84
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    new-instance p1, Lex0/n;

    .line 88
    .line 89
    const/4 v1, 0x0

    .line 90
    invoke-direct {p1, p0, v1}, Lex0/n;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :cond_0
    move-object v1, p1

    .line 102
    const-string p1, "grpc"

    .line 103
    .line 104
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    if-eqz p1, :cond_1

    .line 109
    .line 110
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;->grpcBuilder()Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    new-instance v2, Lex0/b;

    .line 118
    .line 119
    const/4 v0, 0x0

    .line 120
    invoke-direct {v2, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 121
    .line 122
    .line 123
    new-instance v3, Lex0/b;

    .line 124
    .line 125
    const/4 v0, 0x1

    .line 126
    invoke-direct {v3, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 127
    .line 128
    .line 129
    new-instance v4, Lex0/c;

    .line 130
    .line 131
    const/4 v0, 0x0

    .line 132
    invoke-direct {v4, p1, v0}, Lex0/c;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 133
    .line 134
    .line 135
    new-instance v5, Lex0/b;

    .line 136
    .line 137
    const/4 v0, 0x2

    .line 138
    invoke-direct {v5, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 139
    .line 140
    .line 141
    new-instance v6, Lex0/b;

    .line 142
    .line 143
    const/4 v0, 0x3

    .line 144
    invoke-direct {v6, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 145
    .line 146
    .line 147
    new-instance v7, Lex0/b;

    .line 148
    .line 149
    const/4 v0, 0x4

    .line 150
    invoke-direct {v7, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 151
    .line 152
    .line 153
    new-instance v8, Lex0/c;

    .line 154
    .line 155
    const/4 v0, 0x1

    .line 156
    invoke-direct {v8, p1, v0}, Lex0/c;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 157
    .line 158
    .line 159
    new-instance v9, Lex0/b;

    .line 160
    .line 161
    const/4 v0, 0x5

    .line 162
    invoke-direct {v9, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 163
    .line 164
    .line 165
    new-instance v10, Lex0/b;

    .line 166
    .line 167
    const/4 v0, 0x6

    .line 168
    invoke-direct {v10, p1, v0}, Lex0/b;-><init>(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;I)V

    .line 169
    .line 170
    .line 171
    const-string v0, "logs"

    .line 172
    .line 173
    invoke-static/range {v0 .. v10}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->configureOtlpExporterBuilder(Ljava/lang/String;Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 174
    .line 175
    .line 176
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/internal/OtlpLogRecordExporterProvider;->meterProviderRef:Ljava/util/concurrent/atomic/AtomicReference;

    .line 177
    .line 178
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    new-instance v0, Lex0/n;

    .line 182
    .line 183
    const/4 v1, 0x0

    .line 184
    invoke-direct {v0, p0, v1}, Lex0/n;-><init>(Ljava/lang/Object;I)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1, v0}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->setMeterProvider(Ljava/util/function/Supplier;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 188
    .line 189
    .line 190
    invoke-virtual {p1}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporter;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    return-object p0

    .line 195
    :cond_1
    new-instance p0, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;

    .line 196
    .line 197
    const-string p1, "Unsupported OTLP logs protocol: "

    .line 198
    .line 199
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    throw p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "otlp"

    .line 2
    .line 3
    return-object p0
.end method

.method public grpcBuilder()Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporter;->builder()Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public httpBuilder()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->builder()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
