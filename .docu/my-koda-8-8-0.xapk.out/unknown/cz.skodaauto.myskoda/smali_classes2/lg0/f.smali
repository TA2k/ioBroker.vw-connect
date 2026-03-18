.class public final enum Llg0/f;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Llg0/f;

.field public static final enum f:Llg0/f;

.field public static final enum g:Llg0/f;

.field public static final enum h:Llg0/f;

.field public static final enum i:Llg0/f;

.field public static final enum j:Llg0/f;

.field public static final synthetic k:[Llg0/f;


# instance fields
.field public final d:Z


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Llg0/f;

    .line 2
    .line 3
    const-string v1, "Paused"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Llg0/f;-><init>(Ljava/lang/String;IZ)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Llg0/f;->e:Llg0/f;

    .line 10
    .line 11
    new-instance v1, Llg0/f;

    .line 12
    .line 13
    const-string v3, "Pending"

    .line 14
    .line 15
    const/4 v4, 0x1

    .line 16
    invoke-direct {v1, v3, v4, v2}, Llg0/f;-><init>(Ljava/lang/String;IZ)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Llg0/f;->f:Llg0/f;

    .line 20
    .line 21
    move v3, v2

    .line 22
    new-instance v2, Llg0/f;

    .line 23
    .line 24
    const-string v5, "Running"

    .line 25
    .line 26
    const/4 v6, 0x2

    .line 27
    invoke-direct {v2, v5, v6, v3}, Llg0/f;-><init>(Ljava/lang/String;IZ)V

    .line 28
    .line 29
    .line 30
    sput-object v2, Llg0/f;->g:Llg0/f;

    .line 31
    .line 32
    new-instance v3, Llg0/f;

    .line 33
    .line 34
    const-string v5, "Failed"

    .line 35
    .line 36
    const/4 v6, 0x3

    .line 37
    invoke-direct {v3, v5, v6, v4}, Llg0/f;-><init>(Ljava/lang/String;IZ)V

    .line 38
    .line 39
    .line 40
    sput-object v3, Llg0/f;->h:Llg0/f;

    .line 41
    .line 42
    move v5, v4

    .line 43
    new-instance v4, Llg0/f;

    .line 44
    .line 45
    const-string v6, "Cancelled"

    .line 46
    .line 47
    const/4 v7, 0x4

    .line 48
    invoke-direct {v4, v6, v7, v5}, Llg0/f;-><init>(Ljava/lang/String;IZ)V

    .line 49
    .line 50
    .line 51
    sput-object v4, Llg0/f;->i:Llg0/f;

    .line 52
    .line 53
    move v6, v5

    .line 54
    new-instance v5, Llg0/f;

    .line 55
    .line 56
    const-string v7, "Successful"

    .line 57
    .line 58
    const/4 v8, 0x5

    .line 59
    invoke-direct {v5, v7, v8, v6}, Llg0/f;-><init>(Ljava/lang/String;IZ)V

    .line 60
    .line 61
    .line 62
    sput-object v5, Llg0/f;->j:Llg0/f;

    .line 63
    .line 64
    filled-new-array/range {v0 .. v5}, [Llg0/f;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    sput-object v0, Llg0/f;->k:[Llg0/f;

    .line 69
    .line 70
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 71
    .line 72
    .line 73
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IZ)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-boolean p3, p0, Llg0/f;->d:Z

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llg0/f;
    .locals 1

    .line 1
    const-class v0, Llg0/f;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Llg0/f;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Llg0/f;
    .locals 1

    .line 1
    sget-object v0, Llg0/f;->k:[Llg0/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Llg0/f;

    .line 8
    .line 9
    return-object v0
.end method
