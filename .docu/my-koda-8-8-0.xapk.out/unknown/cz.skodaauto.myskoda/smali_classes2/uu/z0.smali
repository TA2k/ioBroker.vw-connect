.class public final enum Luu/z0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Luu/z0;

.field public static final enum f:Luu/z0;

.field public static final synthetic g:[Luu/z0;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Luu/z0;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Luu/z0;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Luu/z0;

    .line 10
    .line 11
    const-string v2, "NORMAL"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3, v3}, Luu/z0;-><init>(Ljava/lang/String;II)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Luu/z0;->e:Luu/z0;

    .line 18
    .line 19
    new-instance v2, Luu/z0;

    .line 20
    .line 21
    const-string v3, "SATELLITE"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4, v4}, Luu/z0;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Luu/z0;

    .line 28
    .line 29
    const-string v4, "TERRAIN"

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    invoke-direct {v3, v4, v5, v5}, Luu/z0;-><init>(Ljava/lang/String;II)V

    .line 33
    .line 34
    .line 35
    new-instance v4, Luu/z0;

    .line 36
    .line 37
    const-string v5, "HYBRID"

    .line 38
    .line 39
    const/4 v6, 0x4

    .line 40
    invoke-direct {v4, v5, v6, v6}, Luu/z0;-><init>(Ljava/lang/String;II)V

    .line 41
    .line 42
    .line 43
    sput-object v4, Luu/z0;->f:Luu/z0;

    .line 44
    .line 45
    filled-new-array {v0, v1, v2, v3, v4}, [Luu/z0;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sput-object v0, Luu/z0;->g:[Luu/z0;

    .line 50
    .line 51
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Luu/z0;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Luu/z0;
    .locals 1

    .line 1
    const-class v0, Luu/z0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Luu/z0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Luu/z0;
    .locals 1

    .line 1
    sget-object v0, Luu/z0;->g:[Luu/z0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Luu/z0;

    .line 8
    .line 9
    return-object v0
.end method
