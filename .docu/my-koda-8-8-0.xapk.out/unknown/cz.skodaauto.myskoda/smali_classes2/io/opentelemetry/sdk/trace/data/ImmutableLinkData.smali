.class abstract Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/data/LinkData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final DEFAULT_ATTRIBUTE_COLLECTION:Lio/opentelemetry/api/common/Attributes;

.field private static final DEFAULT_ATTRIBUTE_COUNT:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;->DEFAULT_ATTRIBUTE_COLLECTION:Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
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

.method public static create(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/sdk/trace/data/LinkData;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;

    sget-object v1, Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;->DEFAULT_ATTRIBUTE_COLLECTION:Lio/opentelemetry/api/common/Attributes;

    const/4 v2, 0x0

    invoke-direct {v0, p0, v1, v2}, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;-><init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)V

    return-object v0
.end method

.method public static create(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/data/LinkData;
    .locals 2

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;

    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v1

    invoke-direct {v0, p0, p1, v1}, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;-><init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)V

    return-object v0
.end method

.method public static create(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/LinkData;
    .locals 1

    .line 3
    new-instance v0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;

    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;-><init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)V

    return-object v0
.end method
