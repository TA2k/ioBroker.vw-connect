.class public final enum Lkotlin/reflect/jvm/internal/impl/km/MemberKind;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lkotlin/reflect/jvm/internal/impl/km/MemberKind;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

.field public static final enum DECLARATION:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

.field public static final enum DELEGATION:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

.field public static final enum FAKE_OVERRIDE:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

.field public static final enum SYNTHESIZED:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;


# instance fields
.field private final flag:Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;


# direct methods
.method private static final synthetic $values()[Lkotlin/reflect/jvm/internal/impl/km/MemberKind;
    .locals 4

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->DECLARATION:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->FAKE_OVERRIDE:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 4
    .line 5
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->DELEGATION:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 6
    .line 7
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->SYNTHESIZED:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 2
    .line 3
    const-string v1, "DECLARATION"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->DECLARATION:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 10
    .line 11
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 12
    .line 13
    const-string v1, "FAKE_OVERRIDE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->FAKE_OVERRIDE:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 20
    .line 21
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 22
    .line 23
    const-string v1, "DELEGATION"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->DELEGATION:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 30
    .line 31
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 32
    .line 33
    const-string v1, "SYNTHESIZED"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v2}, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->SYNTHESIZED:Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 40
    .line 41
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->$values()[Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->$VALUES:[Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->$ENTRIES:Lsx0/a;

    .line 52
    .line 53
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 5
    .line 6
    sget-object p2, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->MEMBER_KIND:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;

    .line 7
    .line 8
    const-string v0, "MEMBER_KIND"

    .line 9
    .line 10
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p1, p2, p3}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$FlagField;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->flag:Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 17
    .line 18
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lkotlin/reflect/jvm/internal/impl/km/MemberKind;
    .locals 1

    .line 1
    const-class v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lkotlin/reflect/jvm/internal/impl/km/MemberKind;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->$VALUES:[Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkotlin/reflect/jvm/internal/impl/km/MemberKind;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getFlag$kotlin_metadata()Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/MemberKind;->flag:Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 2
    .line 3
    return-object p0
.end method
