.class public interface abstract Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static builder()Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static empty()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->EMPTY:Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract asAttributes()Lio/opentelemetry/api/common/Attributes;
.end method

.method public abstract asMap()Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end method

.method public abstract forEach(Ljava/util/function/BiConsumer;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiConsumer<",
            "-",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;-",
            "Ljava/lang/Object;",
            ">;)V"
        }
    .end annotation
.end method

.method public get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    if-nez p1, :cond_0

    const/4 p0, 0x0

    return-object p0

    .line 1
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->get(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public abstract get(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract isEmpty()Z
.end method

.method public abstract size()I
.end method

.method public abstract toBuilder()Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
.end method
