.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# static fields
.field static final GEN_AI_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final GEN_AI_PROVIDER_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_ENCODING_FORMATS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_FREQUENCY_PENALTY:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_MAX_TOKENS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field static final GEN_AI_REQUEST_MODEL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_PRESENCE_PENALTY:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_SEED:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_STOP_SEQUENCES:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_TEMPERATURE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_TOP_K:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_REQUEST_TOP_P:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private static final GEN_AI_RESPONSE_FINISH_REASONS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field private static final GEN_AI_RESPONSE_ID:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final GEN_AI_RESPONSE_MODEL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final GEN_AI_USAGE_INPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field static final GEN_AI_USAGE_OUTPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "gen_ai.operation.name"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "gen_ai.request.encoding_formats"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_ENCODING_FORMATS:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "gen_ai.request.frequency_penalty"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_FREQUENCY_PENALTY:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    const-string v0, "gen_ai.request.max_tokens"

    .line 26
    .line 27
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_MAX_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const-string v0, "gen_ai.request.model"

    .line 34
    .line 35
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 40
    .line 41
    const-string v0, "gen_ai.request.presence_penalty"

    .line 42
    .line 43
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_PRESENCE_PENALTY:Lio/opentelemetry/api/common/AttributeKey;

    .line 48
    .line 49
    const-string v0, "gen_ai.request.seed"

    .line 50
    .line 51
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_SEED:Lio/opentelemetry/api/common/AttributeKey;

    .line 56
    .line 57
    const-string v0, "gen_ai.request.stop_sequences"

    .line 58
    .line 59
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_STOP_SEQUENCES:Lio/opentelemetry/api/common/AttributeKey;

    .line 64
    .line 65
    const-string v0, "gen_ai.request.temperature"

    .line 66
    .line 67
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_TEMPERATURE:Lio/opentelemetry/api/common/AttributeKey;

    .line 72
    .line 73
    const-string v0, "gen_ai.request.top_k"

    .line 74
    .line 75
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_TOP_K:Lio/opentelemetry/api/common/AttributeKey;

    .line 80
    .line 81
    const-string v0, "gen_ai.request.top_p"

    .line 82
    .line 83
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_TOP_P:Lio/opentelemetry/api/common/AttributeKey;

    .line 88
    .line 89
    const-string v0, "gen_ai.response.finish_reasons"

    .line 90
    .line 91
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_FINISH_REASONS:Lio/opentelemetry/api/common/AttributeKey;

    .line 96
    .line 97
    const-string v0, "gen_ai.response.id"

    .line 98
    .line 99
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 104
    .line 105
    const-string v0, "gen_ai.response.model"

    .line 106
    .line 107
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 112
    .line 113
    const-string v0, "gen_ai.provider.name"

    .line 114
    .line 115
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_PROVIDER_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 120
    .line 121
    const-string v0, "gen_ai.usage.input_tokens"

    .line 122
    .line 123
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_USAGE_INPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 128
    .line 129
    const-string v0, "gen_ai.usage.output_tokens"

    .line 130
    .line 131
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_USAGE_OUTPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 136
    .line 137
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 5
    .line 6
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 0
    .param p4    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p5    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 2
    .line 3
    invoke-interface {p2, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getResponseFinishReasons(Ljava/lang/Object;Ljava/lang/Object;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    if-eqz p2, :cond_0

    .line 8
    .line 9
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result p5

    .line 13
    if-nez p5, :cond_0

    .line 14
    .line 15
    sget-object p5, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_FINISH_REASONS:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    invoke-interface {p1, p5, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 18
    .line 19
    .line 20
    :cond_0
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 21
    .line 22
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 23
    .line 24
    invoke-interface {p5, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getResponseId(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p5

    .line 28
    invoke-static {p1, p2, p5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_RESPONSE_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 34
    .line 35
    invoke-interface {p5, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getResponseModel(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p5

    .line 39
    invoke-static {p1, p2, p5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_USAGE_INPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 43
    .line 44
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 45
    .line 46
    invoke-interface {p5, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getUsageInputTokens(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Long;

    .line 47
    .line 48
    .line 49
    move-result-object p5

    .line 50
    invoke-static {p1, p2, p5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_USAGE_OUTPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 54
    .line 55
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 56
    .line 57
    invoke-interface {p0, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getUsageOutputTokens(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Long;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 4
    .line 5
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getOperationName(Ljava/lang/Object;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_PROVIDER_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 13
    .line 14
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 15
    .line 16
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getSystem(Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_MODEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 26
    .line 27
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestModel(Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_SEED:Lio/opentelemetry/api/common/AttributeKey;

    .line 35
    .line 36
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 37
    .line 38
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestSeed(Ljava/lang/Object;)Ljava/lang/Long;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_ENCODING_FORMATS:Lio/opentelemetry/api/common/AttributeKey;

    .line 46
    .line 47
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 48
    .line 49
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestEncodingFormats(Ljava/lang/Object;)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_FREQUENCY_PENALTY:Lio/opentelemetry/api/common/AttributeKey;

    .line 57
    .line 58
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 59
    .line 60
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestFrequencyPenalty(Ljava/lang/Object;)Ljava/lang/Double;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_MAX_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 68
    .line 69
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 70
    .line 71
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestMaxTokens(Ljava/lang/Object;)Ljava/lang/Long;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_PRESENCE_PENALTY:Lio/opentelemetry/api/common/AttributeKey;

    .line 79
    .line 80
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 81
    .line 82
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestPresencePenalty(Ljava/lang/Object;)Ljava/lang/Double;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_STOP_SEQUENCES:Lio/opentelemetry/api/common/AttributeKey;

    .line 90
    .line 91
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 92
    .line 93
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestStopSequences(Ljava/lang/Object;)Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_TEMPERATURE:Lio/opentelemetry/api/common/AttributeKey;

    .line 101
    .line 102
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 103
    .line 104
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestTemperature(Ljava/lang/Object;)Ljava/lang/Double;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_TOP_K:Lio/opentelemetry/api/common/AttributeKey;

    .line 112
    .line 113
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 114
    .line 115
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestTopK(Ljava/lang/Object;)Ljava/lang/Double;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_REQUEST_TOP_P:Lio/opentelemetry/api/common/AttributeKey;

    .line 123
    .line 124
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 125
    .line 126
    invoke-interface {p0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestTopP(Ljava/lang/Object;)Ljava/lang/Double;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    return-void
.end method
