.class public final enum Lah/s;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lah/s;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lah/r;

.field public static final d:Ljava/lang/Object;

.field public static final enum e:Lah/s;

.field public static final synthetic f:[Lah/s;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lah/s;

    .line 2
    .line 3
    const-string v1, "ACCEPTED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lah/s;->e:Lah/s;

    .line 10
    .line 11
    new-instance v1, Lah/s;

    .line 12
    .line 13
    const-string v2, "POSTPONED"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lah/s;

    .line 20
    .line 21
    const-string v3, "DECLINED"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    filled-new-array {v0, v1, v2}, [Lah/s;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lah/s;->f:[Lah/s;

    .line 32
    .line 33
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 34
    .line 35
    .line 36
    new-instance v0, Lah/r;

    .line 37
    .line 38
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lah/s;->Companion:Lah/r;

    .line 42
    .line 43
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 44
    .line 45
    new-instance v1, La2/m;

    .line 46
    .line 47
    const/16 v2, 0x19

    .line 48
    .line 49
    invoke-direct {v1, v2}, La2/m;-><init>(I)V

    .line 50
    .line 51
    .line 52
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sput-object v0, Lah/s;->d:Ljava/lang/Object;

    .line 57
    .line 58
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lah/s;
    .locals 1

    .line 1
    const-class v0, Lah/s;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lah/s;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lah/s;
    .locals 1

    .line 1
    sget-object v0, Lah/s;->f:[Lah/s;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lah/s;

    .line 8
    .line 9
    return-object v0
.end method
