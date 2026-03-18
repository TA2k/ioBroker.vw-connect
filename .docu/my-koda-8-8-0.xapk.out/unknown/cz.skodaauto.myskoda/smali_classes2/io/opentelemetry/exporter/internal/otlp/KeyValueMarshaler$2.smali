.class Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/util/function/Consumer<",
        "Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue<",
        "*>;>;"
    }
.end annotation


# instance fields
.field index:I

.field final synthetic val$keyValueMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;


# direct methods
.method public constructor <init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;->val$keyValueMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;->index:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public accept(Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue<",
            "*>;)V"
        }
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;->val$keyValueMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;->index:I

    add-int/lit8 v2, v1, 0x1

    iput v2, p0, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;->index:I

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;->getAttributeKey()Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p0

    invoke-interface {p1}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;->getValue()Ljava/lang/Object;

    move-result-object p1

    .line 4
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->access$000(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    move-result-object p0

    aput-object p0, v0, v1

    return-void
.end method

.method public bridge synthetic accept(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;

    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler$2;->accept(Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;)V

    return-void
.end method
