.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
.implements Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;


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
        "TREQUEST;TRESPONSE;>;",
        "Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;"
    }
.end annotation


# static fields
.field private static final MESSAGING_BATCH_MESSAGE_COUNT:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_CLIENT_ID:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_DESTINATION_ANONYMOUS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_DESTINATION_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_DESTINATION_PARTITION_ID:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_DESTINATION_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_DESTINATION_TEMPORARY:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_MESSAGE_BODY_SIZE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_MESSAGE_CONVERSATION_ID:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_MESSAGE_ENVELOPE_SIZE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_MESSAGE_ID:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_OPERATION:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final MESSAGING_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final TEMP_DESTINATION_NAME:Ljava/lang/String; = "(temporary)"


# instance fields
.field private final capturedHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "messaging.batch.message_count"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_BATCH_MESSAGE_COUNT:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "messaging.client_id"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_CLIENT_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "messaging.destination.anonymous"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_ANONYMOUS:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    const-string v0, "messaging.destination.name"

    .line 26
    .line 27
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const-string v0, "messaging.destination.partition.id"

    .line 34
    .line 35
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_PARTITION_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 40
    .line 41
    const-string v0, "messaging.destination.template"

    .line 42
    .line 43
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 48
    .line 49
    const-string v0, "messaging.destination.temporary"

    .line 50
    .line 51
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_TEMPORARY:Lio/opentelemetry/api/common/AttributeKey;

    .line 56
    .line 57
    const-string v0, "messaging.message.body.size"

    .line 58
    .line 59
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_BODY_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 64
    .line 65
    const-string v0, "messaging.message.conversation_id"

    .line 66
    .line 67
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_CONVERSATION_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 72
    .line 73
    const-string v0, "messaging.message.envelope.size"

    .line 74
    .line 75
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_ENVELOPE_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 80
    .line 81
    const-string v0, "messaging.message.id"

    .line 82
    .line 83
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 88
    .line 89
    const-string v0, "messaging.operation"

    .line 90
    .line 91
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_OPERATION:Lio/opentelemetry/api/common/AttributeKey;

    .line 96
    .line 97
    const-string v0, "messaging.system"

    .line 98
    .line 99
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;

    .line 104
    .line 105
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 7
    .line 8
    new-instance p1, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {p1, p3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->capturedHeaders:Ljava/util/List;

    .line 14
    .line 15
    return-void
.end method

.method public static builder(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->builder(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor$1;->$SwitchMap$io$opentelemetry$instrumentation$api$incubator$semconv$messaging$MessageOperation:[I

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    aget p0, v0, p0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    if-eq p0, v0, :cond_3

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    if-eq p0, v0, :cond_2

    .line 20
    .line 21
    const/4 v0, 0x3

    .line 22
    if-ne p0, v0, :cond_1

    .line 23
    .line 24
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->CONSUMER_PROCESS:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v0, "Can\'t possibly happen"

    .line 30
    .line 31
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_2
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->CONSUMER_RECEIVE:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_3
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->PRODUCER:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 39
    .line 40
    return-object p0
.end method

.method public onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 1
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
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 4
    .line 5
    invoke-interface {p5, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getMessageId(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p5

    .line 9
    invoke-static {p1, p2, p5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_BATCH_MESSAGE_COUNT:Lio/opentelemetry/api/common/AttributeKey;

    .line 13
    .line 14
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 15
    .line 16
    invoke-interface {p5, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getBatchMessageCount(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Long;

    .line 17
    .line 18
    .line 19
    move-result-object p4

    .line 20
    invoke-static {p1, p2, p4}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->capturedHeaders:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    :cond_0
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result p4

    .line 33
    if-eqz p4, :cond_1

    .line 34
    .line 35
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p4

    .line 39
    check-cast p4, Ljava/lang/String;

    .line 40
    .line 41
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 42
    .line 43
    invoke-interface {p5, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getMessageHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object p5

    .line 47
    invoke-interface {p5}, Ljava/util/List;->isEmpty()Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_0

    .line 52
    .line 53
    invoke-static {p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/CapturedMessageHeadersUtil;->attributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 54
    .line 55
    .line 56
    move-result-object p4

    .line 57
    invoke-static {p1, p4, p5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
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
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 4
    .line 5
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getSystem(Ljava/lang/Object;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 13
    .line 14
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->isTemporaryDestination(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_TEMPORARY:Lio/opentelemetry/api/common/AttributeKey;

    .line 21
    .line 22
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 23
    .line 24
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    const-string v0, "(temporary)"

    .line 30
    .line 31
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 36
    .line 37
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 38
    .line 39
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getDestination(Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_TEMPLATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 47
    .line 48
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 49
    .line 50
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getDestinationTemplate(Ljava/lang/Object;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :goto_0
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_PARTITION_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 58
    .line 59
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 60
    .line 61
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getDestinationPartitionId(Ljava/lang/Object;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 69
    .line 70
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->isAnonymousDestination(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    if-eqz p2, :cond_1

    .line 75
    .line 76
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_DESTINATION_ANONYMOUS:Lio/opentelemetry/api/common/AttributeKey;

    .line 77
    .line 78
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 79
    .line 80
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_1
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_CONVERSATION_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 84
    .line 85
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 86
    .line 87
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getConversationId(Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_BODY_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 95
    .line 96
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 97
    .line 98
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getMessageBodySize(Ljava/lang/Object;)Ljava/lang/Long;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_MESSAGE_ENVELOPE_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 106
    .line 107
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 108
    .line 109
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getMessageEnvelopeSize(Ljava/lang/Object;)Ljava/lang/Long;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_CLIENT_ID:Lio/opentelemetry/api/common/AttributeKey;

    .line 117
    .line 118
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 119
    .line 120
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;->getClientId(Ljava/lang/Object;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p3

    .line 124
    invoke-static {p1, p2, p3}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 128
    .line 129
    if-eqz p0, :cond_2

    .line 130
    .line 131
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;->MESSAGING_OPERATION:Lio/opentelemetry/api/common/AttributeKey;

    .line 132
    .line 133
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;->operationName()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    :cond_2
    return-void
.end method
