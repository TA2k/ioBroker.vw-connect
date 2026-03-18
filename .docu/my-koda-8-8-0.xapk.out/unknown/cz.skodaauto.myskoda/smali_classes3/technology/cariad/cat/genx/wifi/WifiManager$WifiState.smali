.class public final enum Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "WifiState"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\u0008\t\u0008\u0086\u0081\u0002\u0018\u0000 \t2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\tB\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003j\u0002\u0008\u0004j\u0002\u0008\u0005j\u0002\u0008\u0006j\u0002\u0008\u0007j\u0002\u0008\u0008\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;",
        "",
        "<init>",
        "(Ljava/lang/String;I)V",
        "ENABLED",
        "ENABLING",
        "DISABLED",
        "DISABLING",
        "UNKNOWN",
        "Companion",
        "genx_release"
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

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

.field public static final Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

.field public static final enum DISABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

.field public static final enum DISABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

.field public static final enum ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

.field public static final enum ENABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

.field public static final enum UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
    .locals 5

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->DISABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->DISABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 8
    .line 9
    sget-object v4, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 10
    .line 11
    filled-new-array {v0, v1, v2, v3, v4}, [Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

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
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 2
    .line 3
    const-string v1, "ENABLED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 12
    .line 13
    const-string v1, "ENABLING"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 20
    .line 21
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 22
    .line 23
    const-string v1, "DISABLED"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->DISABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 32
    .line 33
    const-string v1, "DISABLING"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->DISABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 40
    .line 41
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 42
    .line 43
    const-string v1, "UNKNOWN"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 50
    .line 51
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->$values()[Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->$VALUES:[Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 56
    .line 57
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->$ENTRIES:Lsx0/a;

    .line 62
    .line 63
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

    .line 70
    .line 71
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
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->$VALUES:[Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 8
    .line 9
    return-object v0
.end method
