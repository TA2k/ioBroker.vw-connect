.class public final enum Lyq0/t;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lgv/a;

.field public static final enum f:Lyq0/t;

.field public static final synthetic g:[Lyq0/t;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lyq0/t;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "DEFINED"

    .line 5
    .line 6
    const-string v3, "Defined"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lyq0/t;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lyq0/t;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    const-string v3, "LOCKED"

    .line 15
    .line 16
    const-string v4, "Locked"

    .line 17
    .line 18
    invoke-direct {v1, v4, v2, v3}, Lyq0/t;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v2, Lyq0/t;

    .line 22
    .line 23
    const/4 v3, 0x2

    .line 24
    const-string v4, "NOT_DEFINED"

    .line 25
    .line 26
    const-string v5, "NotDefined"

    .line 27
    .line 28
    invoke-direct {v2, v5, v3, v4}, Lyq0/t;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    new-instance v3, Lyq0/t;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const-string v5, "UNKNOWN"

    .line 35
    .line 36
    const-string v6, "Unknown"

    .line 37
    .line 38
    invoke-direct {v3, v6, v4, v5}, Lyq0/t;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    sput-object v3, Lyq0/t;->f:Lyq0/t;

    .line 42
    .line 43
    filled-new-array {v0, v1, v2, v3}, [Lyq0/t;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lyq0/t;->g:[Lyq0/t;

    .line 48
    .line 49
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 50
    .line 51
    .line 52
    new-instance v0, Lgv/a;

    .line 53
    .line 54
    const/16 v1, 0x1b

    .line 55
    .line 56
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lyq0/t;->e:Lgv/a;

    .line 60
    .line 61
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lyq0/t;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lyq0/t;
    .locals 1

    .line 1
    const-class v0, Lyq0/t;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lyq0/t;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lyq0/t;
    .locals 1

    .line 1
    sget-object v0, Lyq0/t;->g:[Lyq0/t;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lyq0/t;

    .line 8
    .line 9
    return-object v0
.end method
