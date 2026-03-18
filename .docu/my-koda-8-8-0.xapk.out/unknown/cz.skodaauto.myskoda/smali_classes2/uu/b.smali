.class public final enum Luu/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Luu/a;

.field public static final enum f:Luu/b;

.field public static final enum g:Luu/b;

.field public static final enum h:Luu/b;

.field public static final synthetic i:[Luu/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Luu/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, -0x2

    .line 5
    const-string v3, "UNKNOWN"

    .line 6
    .line 7
    invoke-direct {v0, v3, v1, v2}, Luu/b;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Luu/b;->f:Luu/b;

    .line 11
    .line 12
    new-instance v1, Luu/b;

    .line 13
    .line 14
    const/4 v2, -0x1

    .line 15
    const-string v3, "NO_MOVEMENT_YET"

    .line 16
    .line 17
    const/4 v4, 0x1

    .line 18
    invoke-direct {v1, v3, v4, v2}, Luu/b;-><init>(Ljava/lang/String;II)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Luu/b;->g:Luu/b;

    .line 22
    .line 23
    new-instance v2, Luu/b;

    .line 24
    .line 25
    const-string v3, "GESTURE"

    .line 26
    .line 27
    const/4 v5, 0x2

    .line 28
    invoke-direct {v2, v3, v5, v4}, Luu/b;-><init>(Ljava/lang/String;II)V

    .line 29
    .line 30
    .line 31
    sput-object v2, Luu/b;->h:Luu/b;

    .line 32
    .line 33
    new-instance v3, Luu/b;

    .line 34
    .line 35
    const-string v4, "API_ANIMATION"

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    invoke-direct {v3, v4, v6, v5}, Luu/b;-><init>(Ljava/lang/String;II)V

    .line 39
    .line 40
    .line 41
    new-instance v4, Luu/b;

    .line 42
    .line 43
    const-string v5, "DEVELOPER_ANIMATION"

    .line 44
    .line 45
    const/4 v7, 0x4

    .line 46
    invoke-direct {v4, v5, v7, v6}, Luu/b;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    filled-new-array {v0, v1, v2, v3, v4}, [Luu/b;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Luu/b;->i:[Luu/b;

    .line 54
    .line 55
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 56
    .line 57
    .line 58
    new-instance v0, Luu/a;

    .line 59
    .line 60
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 61
    .line 62
    .line 63
    sput-object v0, Luu/b;->e:Luu/a;

    .line 64
    .line 65
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Luu/b;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Luu/b;
    .locals 1

    .line 1
    const-class v0, Luu/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Luu/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Luu/b;
    .locals 1

    .line 1
    sget-object v0, Luu/b;->i:[Luu/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Luu/b;

    .line 8
    .line 9
    return-object v0
.end method
