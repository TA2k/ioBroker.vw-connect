.class public interface abstract Lio/opentelemetry/sdk/logs/data/Body;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/logs/data/Body$Type;
    }
.end annotation

.annotation runtime Ljava/lang/Deprecated;
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static empty()Lio/opentelemetry/sdk/logs/data/Body;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/logs/data/EmptyBody;->INSTANCE:Lio/opentelemetry/sdk/logs/data/EmptyBody;

    .line 2
    .line 3
    return-object v0
.end method

.method public static string(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/data/Body;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/data/StringBody;->create(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/data/Body;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract asString()Ljava/lang/String;
.end method

.method public abstract getType()Lio/opentelemetry/sdk/logs/data/Body$Type;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end method
