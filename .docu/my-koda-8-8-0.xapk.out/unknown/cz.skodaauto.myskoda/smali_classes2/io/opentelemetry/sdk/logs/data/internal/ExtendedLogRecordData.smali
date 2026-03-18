.class public interface abstract Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/data/LogRecordData;


# virtual methods
.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;->getExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->asAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public abstract getExtendedAttributes()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
.end method
