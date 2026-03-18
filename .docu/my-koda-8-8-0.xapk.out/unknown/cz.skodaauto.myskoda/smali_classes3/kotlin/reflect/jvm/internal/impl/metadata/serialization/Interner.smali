.class public final Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final firstIndex:I

.field private final interned:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "TT;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private final parent:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner<",
            "TT;>;"
        }
    .end annotation
.end field


# direct methods
.method private final find(Ljava/lang/Object;)Ljava/lang/Integer;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)",
            "Ljava/lang/Integer;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->parent:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, v0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->interned:Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/HashMap;->size()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->parent:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;

    .line 12
    .line 13
    iget v1, v1, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->firstIndex:I

    .line 14
    .line 15
    add-int/2addr v0, v1

    .line 16
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->firstIndex:I

    .line 17
    .line 18
    :cond_0
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->parent:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;

    .line 19
    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->find(Ljava/lang/Object;)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return-object v0

    .line 30
    :cond_2
    :goto_0
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->interned:Ljava/util/HashMap;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/lang/Integer;

    .line 37
    .line 38
    return-object p0
.end method


# virtual methods
.method public final intern(Ljava/lang/Object;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)I"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->find(Ljava/lang/Object;)Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->firstIndex:I

    .line 13
    .line 14
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->interned:Ljava/util/HashMap;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/util/HashMap;->size()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    add-int/2addr v1, v0

    .line 21
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->interned:Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    return v1
.end method
