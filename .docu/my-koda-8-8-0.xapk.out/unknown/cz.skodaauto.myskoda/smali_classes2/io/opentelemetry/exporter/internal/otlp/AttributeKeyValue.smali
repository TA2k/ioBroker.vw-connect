.class public interface abstract Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# direct methods
.method public static synthetic a(Ljava/util/ArrayList;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;->lambda$of$0(Ljava/util/List;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$of$0(Ljava/util/List;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue<",
            "TT;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueImpl;->create(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueImpl;

    move-result-object p0

    return-object p0
.end method

.method public static of(Lio/opentelemetry/api/common/Attributes;)Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/Attributes;",
            ")",
            "Ljava/util/List<",
            "Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValue<",
            "*>;>;"
        }
    .end annotation

    .line 2
    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 3
    new-instance v1, Lio/opentelemetry/api/logs/a;

    const/4 v2, 0x3

    invoke-direct {v1, v0, v2}, Lio/opentelemetry/api/logs/a;-><init>(Ljava/lang/Object;I)V

    invoke-interface {p0, v1}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    return-object v0
.end method


# virtual methods
.method public abstract getAttributeKey()Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation
.end method

.method public abstract getValue()Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation
.end method
