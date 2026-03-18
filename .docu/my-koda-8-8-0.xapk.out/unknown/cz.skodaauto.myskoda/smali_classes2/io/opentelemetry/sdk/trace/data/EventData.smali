.class public interface abstract Lio/opentelemetry/sdk/trace/data/EventData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/data/EventData;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/sdk/trace/data/ImmutableEventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p0

    return-object p0
.end method

.method public static create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;
    .locals 0

    .line 2
    invoke-static {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/trace/data/ImmutableEventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public abstract getAttributes()Lio/opentelemetry/api/common/Attributes;
.end method

.method public getDroppedAttributesCount()I
    .locals 1

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getTotalAttributeCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/EventData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    sub-int/2addr v0, p0

    .line 14
    return v0
.end method

.method public abstract getEpochNanos()J
.end method

.method public abstract getName()Ljava/lang/String;
.end method

.method public abstract getTotalAttributeCount()I
.end method
