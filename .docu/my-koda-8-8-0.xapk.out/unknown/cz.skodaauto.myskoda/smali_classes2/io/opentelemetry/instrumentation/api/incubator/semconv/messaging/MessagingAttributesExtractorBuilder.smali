.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field capturedHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field final operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->capturedHeaders:Ljava/util/List;

    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;

    .line 6
    .line 7
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->capturedHeaders:Ljava/util/List;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessageOperation;Ljava/util/List;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public setCapturedHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingAttributesExtractorBuilder;->capturedHeaders:Ljava/util/List;

    .line 7
    .line 8
    return-object p0
.end method
