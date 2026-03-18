.class public final enum Ltb/s;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltb/s;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Ltb/r;

.field public static final d:Ljava/lang/Object;

.field public static final enum e:Ltb/s;

.field public static final enum f:Ltb/s;

.field public static final enum g:Ltb/s;

.field public static final synthetic h:[Ltb/s;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Ltb/s;

    .line 2
    .line 3
    const-string v1, "REQUIRED_WITH_GRACE_PERIOD"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltb/s;->e:Ltb/s;

    .line 10
    .line 11
    new-instance v1, Ltb/s;

    .line 12
    .line 13
    const-string v2, "REQUIRED_IMMEDIATELY"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Ltb/s;->f:Ltb/s;

    .line 20
    .line 21
    new-instance v2, Ltb/s;

    .line 22
    .line 23
    const-string v3, "NOT_REQUIRED"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Ltb/s;->g:Ltb/s;

    .line 30
    .line 31
    new-instance v3, Ltb/s;

    .line 32
    .line 33
    const-string v4, "POSTPONED_BY_USER"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    new-instance v4, Ltb/s;

    .line 40
    .line 41
    const-string v5, "UNCERTAIN"

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    filled-new-array {v0, v1, v2, v3, v4}, [Ltb/s;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Ltb/s;->h:[Ltb/s;

    .line 52
    .line 53
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 54
    .line 55
    .line 56
    new-instance v0, Ltb/r;

    .line 57
    .line 58
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 59
    .line 60
    .line 61
    sput-object v0, Ltb/s;->Companion:Ltb/r;

    .line 62
    .line 63
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 64
    .line 65
    new-instance v1, Lt61/d;

    .line 66
    .line 67
    const/16 v2, 0x8

    .line 68
    .line 69
    invoke-direct {v1, v2}, Lt61/d;-><init>(I)V

    .line 70
    .line 71
    .line 72
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    sput-object v0, Ltb/s;->d:Ljava/lang/Object;

    .line 77
    .line 78
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ltb/s;
    .locals 1

    .line 1
    const-class v0, Ltb/s;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltb/s;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltb/s;
    .locals 1

    .line 1
    sget-object v0, Ltb/s;->h:[Ltb/s;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltb/s;

    .line 8
    .line 9
    return-object v0
.end method
