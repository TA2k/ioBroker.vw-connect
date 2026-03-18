.class abstract Lio/opentelemetry/sdk/trace/data/ImmutableEventData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/data/EventData;


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

.method public static create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/data/EventData;
    .locals 1

    .line 1
    invoke-interface {p3}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    invoke-static {p0, p1, p2, p3, v0}, Lio/opentelemetry/sdk/trace/data/ImmutableEventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p0

    return-object p0
.end method

.method public static create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;
    .locals 6

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableEventData;

    move-wide v3, p0

    move-object v1, p2

    move-object v2, p3

    move v5, p4

    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableEventData;-><init>(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JI)V

    return-object v0
.end method
