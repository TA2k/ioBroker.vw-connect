.class public interface abstract Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract getBoolean(Ljava/lang/String;Z)Z
.end method

.method public abstract getConfigProvider()Lio/opentelemetry/api/incubator/config/ConfigProvider;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getDeclarativeConfig(Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
.end method

.method public abstract getDouble(Ljava/lang/String;D)D
.end method

.method public abstract getDuration(Ljava/lang/String;Ljava/time/Duration;)Ljava/time/Duration;
.end method

.method public abstract getInt(Ljava/lang/String;I)I
.end method

.method public getList(Ljava/lang/String;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getList(Ljava/lang/String;Ljava/util/List;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public abstract getList(Ljava/lang/String;Ljava/util/List;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getLong(Ljava/lang/String;J)J
.end method

.method public abstract getMap(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getString(Ljava/lang/String;)Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
.end method

.method public abstract isDeclarative()Z
.end method
