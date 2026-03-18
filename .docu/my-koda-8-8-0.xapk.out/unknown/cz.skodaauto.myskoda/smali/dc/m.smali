.class public final enum Ldc/m;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ldc/m;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Ldc/l;

.field public static final d:Ljava/lang/Object;

.field public static final synthetic e:[Ldc/m;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ldc/m;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Ldc/m;

    .line 10
    .line 11
    const-string v2, "REMIND_ME_LATER"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    filled-new-array {v0, v1}, [Ldc/m;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Ldc/m;->e:[Ldc/m;

    .line 22
    .line 23
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 24
    .line 25
    .line 26
    new-instance v0, Ldc/l;

    .line 27
    .line 28
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    sput-object v0, Ldc/m;->Companion:Ldc/l;

    .line 32
    .line 33
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 34
    .line 35
    new-instance v1, Ldc/a;

    .line 36
    .line 37
    const/4 v2, 0x5

    .line 38
    invoke-direct {v1, v2}, Ldc/a;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Ldc/m;->d:Ljava/lang/Object;

    .line 46
    .line 47
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ldc/m;
    .locals 1

    .line 1
    const-class v0, Ldc/m;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ldc/m;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ldc/m;
    .locals 1

    .line 1
    sget-object v0, Ldc/m;->e:[Ldc/m;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ldc/m;

    .line 8
    .line 9
    return-object v0
.end method
