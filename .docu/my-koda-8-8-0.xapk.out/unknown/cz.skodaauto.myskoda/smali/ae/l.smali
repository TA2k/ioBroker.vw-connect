.class public final enum Lae/l;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lae/l;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lae/k;

.field public static final d:Ljava/lang/Object;

.field public static final synthetic e:[Lae/l;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lae/l;

    .line 2
    .line 3
    const-string v1, "AVAILABLE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lae/l;

    .line 10
    .line 11
    const-string v2, "UNAVAILABLE"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lae/l;

    .line 18
    .line 19
    const-string v3, "UNKNOWN"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    filled-new-array {v0, v1, v2}, [Lae/l;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lae/l;->e:[Lae/l;

    .line 30
    .line 31
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 32
    .line 33
    .line 34
    new-instance v0, Lae/k;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lae/l;->Companion:Lae/k;

    .line 40
    .line 41
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 42
    .line 43
    new-instance v1, La2/m;

    .line 44
    .line 45
    const/16 v2, 0x11

    .line 46
    .line 47
    invoke-direct {v1, v2}, La2/m;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lae/l;->d:Ljava/lang/Object;

    .line 55
    .line 56
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lae/l;
    .locals 1

    .line 1
    const-class v0, Lae/l;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lae/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lae/l;
    .locals 1

    .line 1
    sget-object v0, Lae/l;->e:[Lae/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lae/l;

    .line 8
    .line 9
    return-object v0
.end method
