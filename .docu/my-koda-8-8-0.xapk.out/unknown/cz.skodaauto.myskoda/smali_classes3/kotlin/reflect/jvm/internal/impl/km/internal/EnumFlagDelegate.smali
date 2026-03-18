.class public final Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<Node:",
        "Ljava/lang/Object;",
        "E:",
        "Ljava/lang/Enum<",
        "TE;>;>",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final entries:Lsx0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lsx0/a;"
        }
    .end annotation
.end field

.field private final flagValues:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;",
            ">;"
        }
    .end annotation
.end field

.field private final flags:Lhy0/l;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lhy0/l;"
        }
    .end annotation
.end field

.field private final protoSet:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLite;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lhy0/l;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;Lsx0/a;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lhy0/l;",
            "Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLite;",
            ">;",
            "Lsx0/a;",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "flags"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "protoSet"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "entries"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "flagValues"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->flags:Lhy0/l;

    .line 25
    .line 26
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->protoSet:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;

    .line 27
    .line 28
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->entries:Lsx0/a;

    .line 29
    .line 30
    iput-object p4, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->flagValues:Ljava/util/List;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Enum;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TNode;",
            "Lhy0/z;",
            ")TE;"
        }
    .end annotation

    .line 1
    const-string v0, "property"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->entries:Lsx0/a;

    .line 7
    .line 8
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->protoSet:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;

    .line 9
    .line 10
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/EnumFlagDelegate;->flags:Lhy0/l;

    .line 11
    .line 12
    invoke-interface {p0, p1}, Lhy0/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/lang/Number;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLite;

    .line 27
    .line 28
    invoke-interface {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLite;->getNumber()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-interface {p2, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/lang/Enum;

    .line 37
    .line 38
    return-object p0
.end method
