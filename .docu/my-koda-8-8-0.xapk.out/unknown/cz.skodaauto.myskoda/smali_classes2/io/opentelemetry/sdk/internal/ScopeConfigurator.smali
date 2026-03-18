.class public interface abstract Lio/opentelemetry/sdk/internal/ScopeConfigurator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/function/Function<",
        "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
        "TT;>;"
    }
.end annotation

.annotation runtime Ljava/lang/FunctionalInterface;
.end annotation


# direct methods
.method public static builder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;-><init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method


# virtual methods
.method public toBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;-><init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
