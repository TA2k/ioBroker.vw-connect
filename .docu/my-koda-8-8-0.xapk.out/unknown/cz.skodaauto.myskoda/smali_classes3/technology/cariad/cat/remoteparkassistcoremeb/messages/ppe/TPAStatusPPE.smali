.class public final enum Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\u0008\u0008\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003j\u0002\u0008\u0004j\u0002\u0008\u0005j\u0002\u0008\u0006j\u0002\u0008\u0007j\u0002\u0008\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;",
        "",
        "<init>",
        "(Ljava/lang/String;I)V",
        "NOT_POSSIBLE",
        "TEMP_NOT_AVAILABLE",
        "AVAILABLE",
        "ACTIVE",
        "UNDEFINED_1",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

.field public static final enum ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

.field public static final enum AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

.field public static final enum NOT_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

.field public static final enum TEMP_NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

.field public static final enum UNDEFINED_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;
    .locals 5

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->NOT_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->TEMP_NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 8
    .line 9
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->UNDEFINED_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 10
    .line 11
    filled-new-array {v0, v1, v2, v3, v4}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 2
    .line 3
    const-string v1, "NOT_POSSIBLE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->NOT_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 12
    .line 13
    const-string v1, "TEMP_NOT_AVAILABLE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->TEMP_NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 20
    .line 21
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 22
    .line 23
    const-string v1, "AVAILABLE"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 32
    .line 33
    const-string v1, "ACTIVE"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 40
    .line 41
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 42
    .line 43
    const-string v1, "UNDEFINED_1"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->UNDEFINED_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 50
    .line 51
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->$values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->$VALUES:[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 56
    .line 57
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->$ENTRIES:Lsx0/a;

    .line 62
    .line 63
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
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
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->$VALUES:[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 8
    .line 9
    return-object v0
.end method
