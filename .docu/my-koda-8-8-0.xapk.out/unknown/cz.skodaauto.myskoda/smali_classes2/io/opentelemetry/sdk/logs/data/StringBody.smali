.class abstract Lio/opentelemetry/sdk/logs/data/StringBody;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/data/Body;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/data/Body;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/data/AutoValue_StringBody;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/logs/data/AutoValue_StringBody;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract asString()Ljava/lang/String;
.end method

.method public final getType()Lio/opentelemetry/sdk/logs/data/Body$Type;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/logs/data/Body$Type;->STRING:Lio/opentelemetry/sdk/logs/data/Body$Type;

    .line 2
    .line 3
    return-object p0
.end method
