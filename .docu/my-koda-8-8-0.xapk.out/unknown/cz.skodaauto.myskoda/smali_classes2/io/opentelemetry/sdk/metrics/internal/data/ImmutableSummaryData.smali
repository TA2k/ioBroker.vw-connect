.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/SummaryData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final EMPTY:Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;->create(Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;->EMPTY:Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/SummaryPointData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSummaryData;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSummaryData;-><init>(Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static empty()Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;->EMPTY:Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryData;

    .line 2
    .line 3
    return-object v0
.end method
