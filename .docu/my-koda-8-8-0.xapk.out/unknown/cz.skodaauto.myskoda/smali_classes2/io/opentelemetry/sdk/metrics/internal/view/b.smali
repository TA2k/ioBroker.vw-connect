.class public final synthetic Lio/opentelemetry/sdk/metrics/internal/view/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;

.field public final synthetic b:Lio/opentelemetry/api/common/AttributesBuilder;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;Lio/opentelemetry/api/common/AttributesBuilder;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/view/b;->a:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/view/b;->b:Lio/opentelemetry/api/common/AttributesBuilder;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    check-cast p2, Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/view/b;->a:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;

    .line 6
    .line 7
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/b;->b:Lio/opentelemetry/api/common/AttributesBuilder;

    .line 8
    .line 9
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;->a(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
