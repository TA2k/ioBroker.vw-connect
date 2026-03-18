.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiSpanNameExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter<",
            "TREQUEST;*>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 5
    .line 6
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiSpanNameExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public extract(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getOperationName(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesGetter;->getRequestModel(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const/16 v0, 0x20

    .line 25
    .line 26
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
