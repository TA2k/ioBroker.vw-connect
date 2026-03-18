.class public final enum Lcd/g;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcd/g;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lcd/f;

.field public static final d:Ljava/lang/Object;

.field public static final synthetic e:[Lcd/g;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lcd/g;

    .line 2
    .line 3
    const-string v1, "RFIDCard"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lcd/g;

    .line 10
    .line 11
    const-string v2, "WallBox"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lcd/g;

    .line 18
    .line 19
    const-string v3, "App"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lcd/g;

    .line 26
    .line 27
    const-string v4, "Date"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    filled-new-array {v0, v1, v2, v3}, [Lcd/g;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lcd/g;->e:[Lcd/g;

    .line 38
    .line 39
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 40
    .line 41
    .line 42
    new-instance v0, Lcd/f;

    .line 43
    .line 44
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lcd/g;->Companion:Lcd/f;

    .line 48
    .line 49
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 50
    .line 51
    new-instance v1, Lc91/u;

    .line 52
    .line 53
    const/16 v2, 0x10

    .line 54
    .line 55
    invoke-direct {v1, v2}, Lc91/u;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sput-object v0, Lcd/g;->d:Ljava/lang/Object;

    .line 63
    .line 64
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcd/g;
    .locals 1

    .line 1
    const-class v0, Lcd/g;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcd/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcd/g;
    .locals 1

    .line 1
    sget-object v0, Lcd/g;->e:[Lcd/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcd/g;

    .line 8
    .line 9
    return-object v0
.end method
