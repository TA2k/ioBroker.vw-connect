.class abstract Lio/opentelemetry/api/baggage/ImmutableEntry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/baggage/BaggageEntry;


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

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntryMetadata;)Lio/opentelemetry/api/baggage/ImmutableEntry;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/AutoValue_ImmutableEntry;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/api/baggage/AutoValue_ImmutableEntry;-><init>(Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntryMetadata;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
