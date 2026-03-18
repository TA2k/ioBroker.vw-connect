.class public final enum Lkg/j0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lkg/j0;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lkg/i0;

.field public static final d:Ljava/lang/Object;

.field public static final enum e:Lkg/j0;

.field public static final enum f:Lkg/j0;

.field public static final synthetic g:[Lkg/j0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/j0;

    .line 2
    .line 3
    const-string v1, "UPGRADE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lkg/j0;->e:Lkg/j0;

    .line 10
    .line 11
    new-instance v1, Lkg/j0;

    .line 12
    .line 13
    const-string v2, "FOLLOW_UP"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lkg/j0;->f:Lkg/j0;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Lkg/j0;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lkg/j0;->g:[Lkg/j0;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    new-instance v0, Lkg/i0;

    .line 31
    .line 32
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lkg/j0;->Companion:Lkg/i0;

    .line 36
    .line 37
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 38
    .line 39
    new-instance v1, Ljv0/c;

    .line 40
    .line 41
    const/16 v2, 0x10

    .line 42
    .line 43
    invoke-direct {v1, v2}, Ljv0/c;-><init>(I)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    sput-object v0, Lkg/j0;->d:Ljava/lang/Object;

    .line 51
    .line 52
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lkg/j0;
    .locals 1

    .line 1
    const-class v0, Lkg/j0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkg/j0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lkg/j0;
    .locals 1

    .line 1
    sget-object v0, Lkg/j0;->g:[Lkg/j0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkg/j0;

    .line 8
    .line 9
    return-object v0
.end method
