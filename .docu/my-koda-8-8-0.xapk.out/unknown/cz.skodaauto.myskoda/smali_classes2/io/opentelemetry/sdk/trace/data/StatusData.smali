.class public interface abstract Lio/opentelemetry/sdk/trace/data/StatusData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    const-string p1, ""

    .line 5
    .line 6
    :goto_0
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/trace/data/ImmutableStatusData;->create(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static error()Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/data/ImmutableStatusData;->ERROR:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 2
    .line 3
    return-object v0
.end method

.method public static ok()Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/data/ImmutableStatusData;->OK:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 2
    .line 3
    return-object v0
.end method

.method public static unset()Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/data/ImmutableStatusData;->UNSET:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract getDescription()Ljava/lang/String;
.end method

.method public abstract getStatusCode()Lio/opentelemetry/api/trace/StatusCode;
.end method
