.class abstract Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/baggage/BaggageEntryMetadata;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field static final EMPTY:Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;->create(Ljava/lang/String;)Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;->EMPTY:Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;

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

.method public static create(Ljava/lang/String;)Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "metadata is null"

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/internal/ApiUsageLogger;->log(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;->EMPTY:Lio/opentelemetry/api/baggage/ImmutableEntryMetadata;

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    new-instance v0, Lio/opentelemetry/api/baggage/AutoValue_ImmutableEntryMetadata;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lio/opentelemetry/api/baggage/AutoValue_ImmutableEntryMetadata;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method


# virtual methods
.method public abstract getValue()Ljava/lang/String;
.end method
