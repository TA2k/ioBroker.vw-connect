.class public final enum Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\u0008\t\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003j\u0002\u0008\u0004j\u0002\u0008\u0005j\u0002\u0008\u0006j\u0002\u0008\u0007j\u0002\u0008\u0008j\u0002\u0008\t\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;",
        "",
        "<init>",
        "(Ljava/lang/String;I)V",
        "INIT",
        "NACHLAUF_KL_15_AUS",
        "SPIELSCHUTZ_CAN",
        "NACHLAUF_KL_15_AUS_FLANKE",
        "SPIELSCHUTZ_RH_850",
        "SYSTEMSTOERUNG_DDA",
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

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

.field public static final enum INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

.field public static final enum NACHLAUF_KL_15_AUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

.field public static final enum NACHLAUF_KL_15_AUS_FLANKE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

.field public static final enum SPIELSCHUTZ_CAN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

.field public static final enum SPIELSCHUTZ_RH_850:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

.field public static final enum SYSTEMSTOERUNG_DDA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;
    .locals 6

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->NACHLAUF_KL_15_AUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->SPIELSCHUTZ_CAN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->NACHLAUF_KL_15_AUS_FLANKE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 8
    .line 9
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->SPIELSCHUTZ_RH_850:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 10
    .line 11
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->SYSTEMSTOERUNG_DDA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 2
    .line 3
    const-string v1, "INIT"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 12
    .line 13
    const-string v1, "NACHLAUF_KL_15_AUS"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->NACHLAUF_KL_15_AUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 20
    .line 21
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 22
    .line 23
    const-string v1, "SPIELSCHUTZ_CAN"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->SPIELSCHUTZ_CAN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 32
    .line 33
    const-string v1, "NACHLAUF_KL_15_AUS_FLANKE"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->NACHLAUF_KL_15_AUS_FLANKE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 40
    .line 41
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 42
    .line 43
    const-string v1, "SPIELSCHUTZ_RH_850"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->SPIELSCHUTZ_RH_850:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 50
    .line 51
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 52
    .line 53
    const-string v1, "SYSTEMSTOERUNG_DDA"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->SYSTEMSTOERUNG_DDA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 60
    .line 61
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->$values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->$VALUES:[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->$ENTRIES:Lsx0/a;

    .line 72
    .line 73
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
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;->$VALUES:[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;

    .line 8
    .line 9
    return-object v0
.end method
