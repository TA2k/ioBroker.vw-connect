.class public final enum Llj/d;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Llj/d;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Llj/c;

.field public static final d:Ljava/lang/Object;

.field public static final synthetic e:[Llj/d;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Llj/d;

    .line 2
    .line 3
    const-string v1, "DISABLED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Llj/d;

    .line 10
    .line 11
    const-string v2, "ENABLED"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Llj/d;

    .line 18
    .line 19
    const-string v3, "ERROR"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Llj/d;

    .line 26
    .line 27
    const-string v4, "ERROR_INVALID_PCID"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Llj/d;

    .line 34
    .line 35
    const-string v5, "PENDING_DISABLE"

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    new-instance v5, Llj/d;

    .line 42
    .line 43
    const-string v6, "PENDING_ENABLE"

    .line 44
    .line 45
    const/4 v7, 0x5

    .line 46
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    filled-new-array/range {v0 .. v5}, [Llj/d;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Llj/d;->e:[Llj/d;

    .line 54
    .line 55
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 56
    .line 57
    .line 58
    new-instance v0, Llj/c;

    .line 59
    .line 60
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 61
    .line 62
    .line 63
    sput-object v0, Llj/d;->Companion:Llj/c;

    .line 64
    .line 65
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 66
    .line 67
    new-instance v1, Ll31/b;

    .line 68
    .line 69
    const/16 v2, 0xc

    .line 70
    .line 71
    invoke-direct {v1, v2}, Ll31/b;-><init>(I)V

    .line 72
    .line 73
    .line 74
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    sput-object v0, Llj/d;->d:Ljava/lang/Object;

    .line 79
    .line 80
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llj/d;
    .locals 1

    .line 1
    const-class v0, Llj/d;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Llj/d;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Llj/d;
    .locals 1

    .line 1
    sget-object v0, Llj/d;->e:[Llj/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Llj/d;

    .line 8
    .line 9
    return-object v0
.end method
