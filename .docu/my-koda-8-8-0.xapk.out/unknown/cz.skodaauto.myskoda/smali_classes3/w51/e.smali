.class public final enum Lw51/e;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lw51/e;

.field public static final enum f:Lw51/e;

.field public static final synthetic g:[Lw51/e;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lw51/e;

    .line 2
    .line 3
    const-string v1, "VERBOSE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    invoke-direct {v0, v1, v2, v3}, Lw51/e;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Lw51/e;

    .line 11
    .line 12
    const-string v2, "DEBUG"

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    const/4 v5, 0x3

    .line 16
    invoke-direct {v1, v2, v4, v5}, Lw51/e;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lw51/e;

    .line 20
    .line 21
    const-string v4, "INFO"

    .line 22
    .line 23
    const/4 v6, 0x4

    .line 24
    invoke-direct {v2, v4, v3, v6}, Lw51/e;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Lw51/e;

    .line 28
    .line 29
    const-string v4, "WARN"

    .line 30
    .line 31
    const/4 v7, 0x5

    .line 32
    invoke-direct {v3, v4, v5, v7}, Lw51/e;-><init>(Ljava/lang/String;II)V

    .line 33
    .line 34
    .line 35
    sput-object v3, Lw51/e;->e:Lw51/e;

    .line 36
    .line 37
    new-instance v4, Lw51/e;

    .line 38
    .line 39
    const-string v5, "ERROR"

    .line 40
    .line 41
    const/4 v7, 0x6

    .line 42
    invoke-direct {v4, v5, v6, v7}, Lw51/e;-><init>(Ljava/lang/String;II)V

    .line 43
    .line 44
    .line 45
    sput-object v4, Lw51/e;->f:Lw51/e;

    .line 46
    .line 47
    filled-new-array {v0, v1, v2, v3, v4}, [Lw51/e;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lw51/e;->g:[Lw51/e;

    .line 52
    .line 53
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lw51/e;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lw51/e;
    .locals 1

    .line 1
    const-class v0, Lw51/e;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lw51/e;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lw51/e;
    .locals 1

    .line 1
    sget-object v0, Lw51/e;->g:[Lw51/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lw51/e;

    .line 8
    .line 9
    return-object v0
.end method
