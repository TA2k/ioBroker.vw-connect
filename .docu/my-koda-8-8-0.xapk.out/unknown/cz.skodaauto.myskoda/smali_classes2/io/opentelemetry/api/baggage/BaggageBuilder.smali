.class public interface abstract Lio/opentelemetry/api/baggage/BaggageBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract build()Lio/opentelemetry/api/baggage/Baggage;
.end method

.method public put(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/baggage/BaggageBuilder;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/baggage/BaggageEntryMetadata;->empty()Lio/opentelemetry/api/baggage/BaggageEntryMetadata;

    move-result-object v0

    invoke-interface {p0, p1, p2, v0}, Lio/opentelemetry/api/baggage/BaggageBuilder;->put(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntryMetadata;)Lio/opentelemetry/api/baggage/BaggageBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract put(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntryMetadata;)Lio/opentelemetry/api/baggage/BaggageBuilder;
.end method

.method public abstract remove(Ljava/lang/String;)Lio/opentelemetry/api/baggage/BaggageBuilder;
.end method
