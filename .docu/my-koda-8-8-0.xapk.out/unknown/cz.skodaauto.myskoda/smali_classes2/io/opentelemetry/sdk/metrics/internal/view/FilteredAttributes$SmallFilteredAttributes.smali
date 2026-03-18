.class Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;
.super Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "SmallFilteredAttributes"
.end annotation


# static fields
.field private static final BITS_PER_INTEGER:I = 0x20


# instance fields
.field private final filteredIndices:I


# direct methods
.method private constructor <init>([Ljava/lang/Object;III)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, p3, v0}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;-><init>([Ljava/lang/Object;IILio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$1;)V

    .line 3
    iput p4, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;->filteredIndices:I

    return-void
.end method

.method public synthetic constructor <init>([Ljava/lang/Object;IIILio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;-><init>([Ljava/lang/Object;III)V

    return-void
.end method


# virtual methods
.method public includeIndexInOutput(I)Z
    .locals 1

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;->filteredIndices:I

    .line 2
    .line 3
    div-int/lit8 p1, p1, 0x2

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    shl-int p1, v0, p1

    .line 7
    .line 8
    and-int/2addr p0, p1

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    return v0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method
