.class public interface abstract Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
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

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static booleanArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/Boolean;",
            ">;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->booleanArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static doubleArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->doubleArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static extendedAttributesKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributes;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->EXTENDED_ATTRIBUTES:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->toExtendedAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static longArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->longArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static longKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static stringKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public asAttributeKey()Lio/opentelemetry/api/common/AttributeKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->toAttributeKey(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public abstract getKey()Ljava/lang/String;
.end method

.method public abstract getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;
.end method
