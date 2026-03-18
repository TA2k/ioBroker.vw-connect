.class public final synthetic Lio/opentelemetry/sdk/trace/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/trace/SpanCallable;
.implements Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;


# instance fields
.field public final synthetic a:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/b;->a:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public callInSpan()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/b;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lio/opentelemetry/api/incubator/trace/SpanRunnable;

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/ExtendedSdkSpanBuilder;->c(Lio/opentelemetry/api/incubator/trace/SpanRunnable;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/b;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/internal/AttributesMap;->putIfCapacity(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
