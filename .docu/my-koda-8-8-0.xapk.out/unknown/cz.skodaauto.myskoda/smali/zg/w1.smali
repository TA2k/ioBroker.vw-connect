.class public final enum Lzg/w1;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lzg/w1;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lzg/v1;

.field public static final d:Ljava/lang/Object;

.field public static final synthetic e:[Lzg/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lzg/w1;

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
    new-instance v1, Lzg/w1;

    .line 10
    .line 11
    const-string v2, "SOLAR_AND_GRIND"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lzg/w1;

    .line 18
    .line 19
    const-string v3, "SOLAR_ONLY"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lzg/w1;

    .line 26
    .line 27
    const-string v4, "NOT_SUPPORTED"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Lzg/w1;

    .line 34
    .line 35
    const-string v5, "UNKNOWN"

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    filled-new-array {v0, v1, v2, v3, v4}, [Lzg/w1;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lzg/w1;->e:[Lzg/w1;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    new-instance v0, Lzg/v1;

    .line 51
    .line 52
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lzg/w1;->Companion:Lzg/v1;

    .line 56
    .line 57
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 58
    .line 59
    new-instance v1, Lz81/g;

    .line 60
    .line 61
    const/16 v2, 0x18

    .line 62
    .line 63
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 64
    .line 65
    .line 66
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sput-object v0, Lzg/w1;->d:Ljava/lang/Object;

    .line 71
    .line 72
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lzg/w1;
    .locals 1

    .line 1
    const-class v0, Lzg/w1;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lzg/w1;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lzg/w1;
    .locals 1

    .line 1
    sget-object v0, Lzg/w1;->e:[Lzg/w1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lzg/w1;

    .line 8
    .line 9
    return-object v0
.end method
