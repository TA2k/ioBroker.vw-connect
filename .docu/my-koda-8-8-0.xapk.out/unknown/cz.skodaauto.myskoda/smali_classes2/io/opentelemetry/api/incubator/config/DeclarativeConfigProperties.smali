.class public interface abstract Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static empty()Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/incubator/config/EmptyDeclarativeConfigProperties;->getInstance()Lio/opentelemetry/api/incubator/config/EmptyDeclarativeConfigProperties;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static toMap(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigPropertyUtil;->toMap(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getBoolean(Ljava/lang/String;)Ljava/lang/Boolean;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getBoolean(Ljava/lang/String;Z)Z
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getBoolean(Ljava/lang/String;)Ljava/lang/Boolean;

    move-result-object p0

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p0, p1}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0
.end method

.method public abstract getComponentLoader()Lio/opentelemetry/common/ComponentLoader;
.end method

.method public getDouble(Ljava/lang/String;D)D
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getDouble(Ljava/lang/String;)Ljava/lang/Double;

    move-result-object p0

    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    invoke-static {p0, p1}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Double;

    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    move-result-wide p0

    return-wide p0
.end method

.method public abstract getDouble(Ljava/lang/String;)Ljava/lang/Double;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getInt(Ljava/lang/String;I)I
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getInt(Ljava/lang/String;)Ljava/lang/Integer;

    move-result-object p0

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {p0, p1}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Integer;

    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    move-result p0

    return p0
.end method

.method public abstract getInt(Ljava/lang/String;)Ljava/lang/Integer;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getLong(Ljava/lang/String;J)J
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getLong(Ljava/lang/String;)Ljava/lang/Long;

    move-result-object p0

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p1

    invoke-static {p0, p1}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Long;

    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    move-result-wide p0

    return-wide p0
.end method

.method public abstract getLong(Ljava/lang/String;)Ljava/lang/Long;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getPropertyKeys()Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getScalarList(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/String;",
            "Ljava/lang/Class<",
            "TT;>;)",
            "Ljava/util/List<",
            "TT;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getScalarList(Ljava/lang/String;Ljava/lang/Class;Ljava/util/List;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/String;",
            "Ljava/lang/Class<",
            "TT;>;",
            "Ljava/util/List<",
            "TT;>;)",
            "Ljava/util/List<",
            "TT;>;"
        }
    .end annotation

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getScalarList(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;

    move-result-object p0

    invoke-static {p0, p3}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/util/List;

    return-object p0
.end method

.method public abstract getString(Ljava/lang/String;)Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p2}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/String;

    return-object p0
.end method

.method public abstract getStructured(Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getStructured(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getStructured(Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    move-result-object p0

    invoke-static {p0, p2}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    return-object p0
.end method

.method public abstract getStructuredList(Ljava/lang/String;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getStructuredList(Ljava/lang/String;Ljava/util/List;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;",
            ">;)",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getStructuredList(Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    invoke-static {p0, p2}, Lio/opentelemetry/api/internal/ConfigUtil;->defaultIfNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/util/List;

    return-object p0
.end method
