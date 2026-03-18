.class public final enum Lxw0/f;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lwe0/b;

.field public static final synthetic e:[Lxw0/f;

.field public static final synthetic f:Lsx0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lxw0/f;

    .line 2
    .line 3
    const-string v1, "MONDAY"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lxw0/f;

    .line 10
    .line 11
    const-string v2, "TUESDAY"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lxw0/f;

    .line 18
    .line 19
    const-string v3, "WEDNESDAY"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lxw0/f;

    .line 26
    .line 27
    const-string v4, "THURSDAY"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Lxw0/f;

    .line 34
    .line 35
    const-string v5, "FRIDAY"

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    new-instance v5, Lxw0/f;

    .line 42
    .line 43
    const-string v6, "SATURDAY"

    .line 44
    .line 45
    const/4 v7, 0x5

    .line 46
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    new-instance v6, Lxw0/f;

    .line 50
    .line 51
    const-string v7, "SUNDAY"

    .line 52
    .line 53
    const/4 v8, 0x6

    .line 54
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 55
    .line 56
    .line 57
    filled-new-array/range {v0 .. v6}, [Lxw0/f;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    sput-object v0, Lxw0/f;->e:[Lxw0/f;

    .line 62
    .line 63
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    sput-object v0, Lxw0/f;->f:Lsx0/b;

    .line 68
    .line 69
    new-instance v0, Lwe0/b;

    .line 70
    .line 71
    const/16 v1, 0x1a

    .line 72
    .line 73
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 74
    .line 75
    .line 76
    sput-object v0, Lxw0/f;->d:Lwe0/b;

    .line 77
    .line 78
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lxw0/f;
    .locals 1

    .line 1
    const-class v0, Lxw0/f;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lxw0/f;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lxw0/f;
    .locals 1

    .line 1
    sget-object v0, Lxw0/f;->e:[Lxw0/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lxw0/f;

    .line 8
    .line 9
    return-object v0
.end method
