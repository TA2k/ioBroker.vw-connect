.class public abstract Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableTable;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<Element:",
        "Lkotlin/reflect/jvm/internal/impl/protobuf/GeneratedMessageLite$Builder<",
        "*TElement;>;Table:",
        "Lkotlin/reflect/jvm/internal/impl/protobuf/GeneratedMessageLite;",
        "TableBuilder:",
        "Lkotlin/reflect/jvm/internal/impl/protobuf/GeneratedMessageLite$Builder<",
        "TTable;TTableBuilder;>;>",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final interner:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner<",
            "Lkotlin/reflect/jvm/internal/impl/metadata/serialization/TableElementWrapper<",
            "TElement;>;>;"
        }
    .end annotation
.end field


# virtual methods
.method public final get(Lkotlin/reflect/jvm/internal/impl/protobuf/GeneratedMessageLite$Builder;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TElement;)I"
        }
    .end annotation

    .line 1
    const-string v0, "type"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableTable;->interner:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;

    .line 7
    .line 8
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/TableElementWrapper;

    .line 9
    .line 10
    invoke-direct {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/TableElementWrapper;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/GeneratedMessageLite$Builder;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/Interner;->intern(Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method
