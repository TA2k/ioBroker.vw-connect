.class public final enum Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

.field public static final enum IN:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

.field public static final enum INV:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

.field public static final enum OUT:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;


# instance fields
.field private final presentation:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;
    .locals 3

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->IN:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->OUT:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 4
    .line 5
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->INV:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "in"

    .line 5
    .line 6
    const-string v3, "IN"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->IN:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 12
    .line 13
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    const-string v2, "out"

    .line 17
    .line 18
    const-string v3, "OUT"

    .line 19
    .line 20
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->OUT:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 24
    .line 25
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    const-string v2, ""

    .line 29
    .line 30
    const-string v3, "INV"

    .line 31
    .line 32
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->INV:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 36
    .line 37
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->$values()[Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->$VALUES:[Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 42
    .line 43
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->$ENTRIES:Lsx0/a;

    .line 48
    .line 49
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->presentation:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;
    .locals 1

    .line 1
    const-class v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->$VALUES:[Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->presentation:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
