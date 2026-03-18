.class public interface abstract Lio/opentelemetry/sdk/metrics/data/SummaryData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/Data;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/metrics/data/Data<",
        "Lio/opentelemetry/sdk/metrics/data/SummaryPointData;",
        ">;"
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/data/SummaryData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/SummaryPointData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/SummaryData;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;->create(Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
