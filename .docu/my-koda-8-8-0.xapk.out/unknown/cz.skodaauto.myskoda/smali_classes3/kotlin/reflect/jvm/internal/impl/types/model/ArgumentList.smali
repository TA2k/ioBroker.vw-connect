.class public final Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;
.super Ljava/util/ArrayList;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/util/ArrayList<",
        "Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;",
        ">;",
        "Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;"
    }
.end annotation


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final bridge contains(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    if-nez v0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;->contains(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Z

    move-result p0

    return p0
.end method

.method public bridge contains(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Z
    .locals 0

    .line 2
    invoke-super {p0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method

.method public bridge getSize()I
    .locals 0

    .line 1
    invoke-super {p0}, Ljava/util/ArrayList;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final bridge indexOf(Ljava/lang/Object;)I
    .locals 1

    .line 1
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    if-nez v0, :cond_0

    const/4 p0, -0x1

    return p0

    :cond_0
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;->indexOf(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)I

    move-result p0

    return p0
.end method

.method public bridge indexOf(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)I
    .locals 0

    .line 2
    invoke-super {p0, p1}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    move-result p0

    return p0
.end method

.method public final bridge lastIndexOf(Ljava/lang/Object;)I
    .locals 1

    .line 1
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    if-nez v0, :cond_0

    const/4 p0, -0x1

    return p0

    :cond_0
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;->lastIndexOf(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)I

    move-result p0

    return p0
.end method

.method public bridge lastIndexOf(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)I
    .locals 0

    .line 2
    invoke-super {p0, p1}, Ljava/util/ArrayList;->lastIndexOf(Ljava/lang/Object;)I

    move-result p0

    return p0
.end method

.method public final bridge remove(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    if-nez v0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;->remove(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Z

    move-result p0

    return p0
.end method

.method public bridge remove(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Z
    .locals 0

    .line 2
    invoke-super {p0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method

.method public final bridge size()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;->getSize()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
