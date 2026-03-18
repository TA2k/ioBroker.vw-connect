.class Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->createForExtendedAttributes(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/util/function/BiConsumer<",
        "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
        "*>;",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field index:I

.field final synthetic val$marshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;


# direct methods
.method public constructor <init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;->val$marshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;->index:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public accept(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            ")V"
        }
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;->val$marshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;->index:I

    add-int/lit8 v2, v1, 0x1

    iput v2, p0, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;->index:I

    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->access$000(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    move-result-object p0

    aput-object p0, v0, v1

    return-void
.end method

.method public bridge synthetic accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil$1;->accept(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    return-void
.end method
