.class public final Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<Node:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final flag:Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

.field private final flags:Lhy0/l;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lhy0/l;"
        }
    .end annotation
.end field

.field private final mask:I


# direct methods
.method public constructor <init>(Lhy0/l;Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lhy0/l;",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;",
            ")V"
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
    const-string v0, "flag"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->flags:Lhy0/l;

    .line 15
    .line 16
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->flag:Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 17
    .line 18
    invoke-virtual {p2}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->getBitWidth$kotlin_metadata()I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    const/4 v0, 0x1

    .line 23
    if-ne p1, v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p2}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->getValue$kotlin_metadata()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-ne p1, v0, :cond_0

    .line 30
    .line 31
    invoke-virtual {p2}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->getOffset$kotlin_metadata()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    shl-int p1, v0, p1

    .line 36
    .line 37
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->mask:I

    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    const-string p1, "BooleanFlagDelegate can work only with boolean flags (bitWidth = 1 and value = 1), but "

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p1, " was passed"

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p1
.end method


# virtual methods
.method public final getValue(Ljava/lang/Object;Lhy0/z;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TNode;",
            "Lhy0/z;",
            ")Z"
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
    iget-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->flag:Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 7
    .line 8
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->flags:Lhy0/l;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lhy0/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-virtual {p2, p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->invoke(I)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0
.end method

.method public final setValue(Ljava/lang/Object;Lhy0/z;Z)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TNode;",
            "Lhy0/z;",
            "Z)V"
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
    iget-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->flags:Lhy0/l;

    .line 7
    .line 8
    invoke-interface {p2, p1}, Lhy0/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    check-cast p2, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p3, :cond_0

    .line 19
    .line 20
    iget p3, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->mask:I

    .line 21
    .line 22
    or-int/2addr p2, p3

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iget p3, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->mask:I

    .line 25
    .line 26
    not-int p3, p3

    .line 27
    and-int/2addr p2, p3

    .line 28
    :goto_0
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->flags:Lhy0/l;

    .line 29
    .line 30
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    invoke-interface {p0, p1, p2}, Lhy0/l;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
