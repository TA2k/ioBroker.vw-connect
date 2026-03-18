.class public final Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final bitWidth:I

.field private final offset:I

.field private final value:I


# direct methods
.method public constructor <init>(III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->offset:I

    iput p2, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->bitWidth:I

    iput p3, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->value:I

    return-void
.end method

.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;)V
    .locals 1

    const-string v0, "field"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x1

    .line 3
    invoke-direct {p0, p1, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;I)V

    return-void
.end method

.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;I)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField<",
            "*>;I)V"
        }
    .end annotation

    const-string v0, "field"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iget v0, p1, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;->offset:I

    iget p1, p1, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;->bitWidth:I

    invoke-direct {p0, v0, p1, p2}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;-><init>(III)V

    return-void
.end method


# virtual methods
.method public final getBitWidth$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->bitWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public final getOffset$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->offset:I

    .line 2
    .line 3
    return p0
.end method

.method public final getValue$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->value:I

    .line 2
    .line 3
    return p0
.end method

.method public final invoke(I)Z
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->offset:I

    .line 2
    .line 3
    ushr-int/2addr p1, v0

    .line 4
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->bitWidth:I

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    shl-int v0, v1, v0

    .line 8
    .line 9
    sub-int/2addr v0, v1

    .line 10
    and-int/2addr p1, v0

    .line 11
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;->value:I

    .line 12
    .line 13
    if-ne p1, p0, :cond_0

    .line 14
    .line 15
    return v1

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method
