.class public final enum Ldc/e;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ldc/e;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Ldc/d;

.field public static final d:Ljava/lang/Object;

.field public static final enum e:Ldc/e;

.field public static final enum f:Ldc/e;

.field public static final synthetic g:[Ldc/e;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ldc/e;

    .line 2
    .line 3
    const-string v1, "AGREE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ldc/e;->e:Ldc/e;

    .line 10
    .line 11
    new-instance v1, Ldc/e;

    .line 12
    .line 13
    const-string v2, "REMIND_ME_LATER"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Ldc/e;->f:Ldc/e;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Ldc/e;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Ldc/e;->g:[Ldc/e;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    new-instance v0, Ldc/d;

    .line 31
    .line 32
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    sput-object v0, Ldc/e;->Companion:Ldc/d;

    .line 36
    .line 37
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 38
    .line 39
    new-instance v1, Ldc/a;

    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    invoke-direct {v1, v2}, Ldc/a;-><init>(I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sput-object v0, Ldc/e;->d:Ljava/lang/Object;

    .line 50
    .line 51
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ldc/e;
    .locals 1

    .line 1
    const-class v0, Ldc/e;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ldc/e;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ldc/e;
    .locals 1

    .line 1
    sget-object v0, Ldc/e;->g:[Ldc/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ldc/e;

    .line 8
    .line 9
    return-object v0
.end method
