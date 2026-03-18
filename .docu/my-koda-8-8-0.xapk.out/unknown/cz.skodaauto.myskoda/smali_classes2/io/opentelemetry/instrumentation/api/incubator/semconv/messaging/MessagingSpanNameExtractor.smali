.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;
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
.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field

.field private final operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;*>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 7
    .line 8
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;*>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)V

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
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->isTemporaryDestination(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-string p1, "(temporary)"

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 13
    .line 14
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getDestination(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    :goto_0
    if-nez p1, :cond_1

    .line 19
    .line 20
    const-string p1, "unknown"

    .line 21
    .line 22
    :cond_1
    const-string v0, " "

    .line 23
    .line 24
    invoke-static {p1, v0}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingSpanNameExtractor;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 29
    .line 30
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;->operationName()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method
