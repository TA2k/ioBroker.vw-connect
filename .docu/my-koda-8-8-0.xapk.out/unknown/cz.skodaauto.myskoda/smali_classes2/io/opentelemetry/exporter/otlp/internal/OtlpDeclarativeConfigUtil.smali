.class public final Lio/opentelemetry/exporter/otlp/internal/OtlpDeclarativeConfigUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/util/function/BiConsumer;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/otlp/internal/OtlpDeclarativeConfigUtil;->lambda$configureOtlpExporterBuilder$0(Ljava/util/function/BiConsumer;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static configureOtlpExporterBuilder(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Ljava/util/function/BiConsumer;Ljava/util/function/Consumer;Ljava/util/function/Consumer;Z)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/common/ComponentLoader;",
            ">;",
            "Ljava/util/function/Consumer<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/function/BiConsumer<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/function/Consumer<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/function/Consumer<",
            "Ljava/time/Duration;",
            ">;",
            "Ljava/util/function/Consumer<",
            "[B>;",
            "Ljava/util/function/BiConsumer<",
            "[B[B>;",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            ">;",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ">;Z)V"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getComponentLoader()Lio/opentelemetry/common/ComponentLoader;

    .line 2
    .line 3
    .line 4
    move-result-object p9

    .line 5
    invoke-interface {p2, p9}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    const-string p2, "endpoint"

    .line 9
    .line 10
    invoke-interface {p1, p2}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2, p11}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->validateEndpoint(Ljava/lang/String;Z)Ljava/net/URL;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    invoke-virtual {p2}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    invoke-interface {p3, p2}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    const-string p2, "headers_list"

    .line 28
    .line 29
    invoke-interface {p1, p2}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    if-eqz p2, :cond_1

    .line 34
    .line 35
    const-string p3, "otel.exporter.otlp.headers"

    .line 36
    .line 37
    invoke-static {p3, p2}, Ljava/util/Collections;->singletonMap(Ljava/lang/Object;Ljava/lang/Object;)Ljava/util/Map;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    invoke-static {p2}, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;->createFromMap(Ljava/util/Map;)Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-static {p2, p0, p4}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->configureOtlpHeaders(Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;Ljava/lang/String;Ljava/util/function/BiConsumer;)V

    .line 46
    .line 47
    .line 48
    :cond_1
    const-string p0, "headers"

    .line 49
    .line 50
    invoke-interface {p1, p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getStructuredList(Ljava/lang/String;)Ljava/util/List;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    if-eqz p0, :cond_2

    .line 55
    .line 56
    new-instance p2, Lex0/a;

    .line 57
    .line 58
    const/4 p3, 0x0

    .line 59
    invoke-direct {p2, p4, p3}, Lex0/a;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    invoke-interface {p0, p2}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    const-string p0, "compression"

    .line 66
    .line 67
    invoke-interface {p1, p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    invoke-interface {p5, p0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :cond_3
    const-string p0, "timeout"

    .line 77
    .line 78
    invoke-interface {p1, p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getInt(Ljava/lang/String;)Ljava/lang/Integer;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-eqz p0, :cond_4

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    int-to-long p2, p0

    .line 89
    invoke-static {p2, p3}, Ljava/time/Duration;->ofMillis(J)Ljava/time/Duration;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-interface {p6, p0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_4
    const-string p0, "certificate_file"

    .line 97
    .line 98
    invoke-interface {p1, p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    const-string p2, "client_key_file"

    .line 103
    .line 104
    invoke-interface {p1, p2}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    const-string p3, "client_certificate_file"

    .line 109
    .line 110
    invoke-interface {p1, p3}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p3

    .line 114
    if-eqz p2, :cond_6

    .line 115
    .line 116
    if-eqz p3, :cond_5

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_5
    new-instance p0, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;

    .line 120
    .line 121
    const-string p1, "client_key_file provided without client_certificate_file - both client_key_file and client_certificate_file must be set"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_6
    :goto_0
    if-nez p2, :cond_8

    .line 128
    .line 129
    if-nez p3, :cond_7

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_7
    new-instance p0, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;

    .line 133
    .line 134
    const-string p1, "client_certificate_file provided without client_key_file - both client_key_file and client_certificate_file must be set"

    .line 135
    .line 136
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/autoconfigure/spi/ConfigurationException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :cond_8
    :goto_1
    invoke-static {p0}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->readFileBytes(Ljava/lang/String;)[B

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-eqz p0, :cond_9

    .line 145
    .line 146
    invoke-interface {p7, p0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :cond_9
    invoke-static {p2}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->readFileBytes(Ljava/lang/String;)[B

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-static {p3}, Lio/opentelemetry/exporter/otlp/internal/OtlpConfigUtil;->readFileBytes(Ljava/lang/String;)[B

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    if-eqz p0, :cond_a

    .line 158
    .line 159
    if-eqz p2, :cond_a

    .line 160
    .line 161
    invoke-interface {p8, p0, p2}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    :cond_a
    invoke-static {p1, p10}, Lio/opentelemetry/exporter/internal/IncubatingExporterBuilderUtil;->configureExporterMemoryMode(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;Ljava/util/function/Consumer;)V

    .line 165
    .line 166
    .line 167
    return-void
.end method

.method public static getStructuredConfigOtlpProtocol(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "protocol"

    .line 2
    .line 3
    const-string v1, "http/protobuf"

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$configureOtlpExporterBuilder$0(Ljava/util/function/BiConsumer;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V
    .locals 2

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "value"

    .line 8
    .line 9
    invoke-interface {p1, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    invoke-interface {p0, v0, p1}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method
