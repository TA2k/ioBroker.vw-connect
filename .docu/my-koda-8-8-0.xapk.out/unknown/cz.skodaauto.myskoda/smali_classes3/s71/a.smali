.class public final enum Ls71/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic d:[Ls71/a;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Ls71/a;

    .line 2
    .line 3
    const-string v1, "SLEEP"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Ls71/a;

    .line 10
    .line 11
    const-string v2, "BATTERY_PROTECTION_CAN"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Ls71/a;

    .line 18
    .line 19
    const-string v3, "MAIN_CONTROLLER_AWAKE_BUS_OFF"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Ls71/a;

    .line 26
    .line 27
    const-string v4, "MAIN_CONTROLLER_AWAKE_BUS_ON"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Ls71/a;

    .line 34
    .line 35
    const-string v5, "PAIRING_ACTIVE"

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    new-instance v5, Ls71/a;

    .line 42
    .line 43
    const-string v6, "FUNCTION_ACTIVE"

    .line 44
    .line 45
    const/4 v7, 0x5

    .line 46
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    new-instance v6, Ls71/a;

    .line 50
    .line 51
    const-string v7, "BATTERY_PROTECTION_ANTENNA"

    .line 52
    .line 53
    const/4 v8, 0x6

    .line 54
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 55
    .line 56
    .line 57
    filled-new-array/range {v0 .. v6}, [Ls71/a;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    sput-object v0, Ls71/a;->d:[Ls71/a;

    .line 62
    .line 63
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 64
    .line 65
    .line 66
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ls71/a;
    .locals 1

    .line 1
    const-class v0, Ls71/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ls71/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ls71/a;
    .locals 1

    .line 1
    sget-object v0, Ls71/a;->d:[Ls71/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ls71/a;

    .line 8
    .line 9
    return-object v0
.end method
