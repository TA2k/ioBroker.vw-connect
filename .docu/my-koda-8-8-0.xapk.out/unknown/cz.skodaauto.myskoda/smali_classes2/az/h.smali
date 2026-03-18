.class public final enum Laz/h;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Laz/h;

.field public static final enum f:Laz/h;

.field public static final enum g:Laz/h;

.field public static final enum h:Laz/h;

.field public static final enum i:Laz/h;

.field public static final synthetic j:[Laz/h;

.field public static final synthetic k:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Laz/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "solo"

    .line 5
    .line 6
    const-string v3, "Solo"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Laz/h;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Laz/h;->e:Laz/h;

    .line 12
    .line 13
    new-instance v1, Laz/h;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "partner"

    .line 17
    .line 18
    const-string v4, "Partner"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Laz/h;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Laz/h;->f:Laz/h;

    .line 24
    .line 25
    new-instance v2, Laz/h;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const-string v4, "children"

    .line 29
    .line 30
    const-string v5, "Children"

    .line 31
    .line 32
    invoke-direct {v2, v5, v3, v4}, Laz/h;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Laz/h;->g:Laz/h;

    .line 36
    .line 37
    new-instance v3, Laz/h;

    .line 38
    .line 39
    const/4 v4, 0x3

    .line 40
    const-string v5, "friends"

    .line 41
    .line 42
    const-string v6, "Friends"

    .line 43
    .line 44
    invoke-direct {v3, v6, v4, v5}, Laz/h;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v3, Laz/h;->h:Laz/h;

    .line 48
    .line 49
    new-instance v4, Laz/h;

    .line 50
    .line 51
    const/4 v5, 0x4

    .line 52
    const-string v6, "senior"

    .line 53
    .line 54
    const-string v7, "Senior"

    .line 55
    .line 56
    invoke-direct {v4, v7, v5, v6}, Laz/h;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v4, Laz/h;->i:Laz/h;

    .line 60
    .line 61
    filled-new-array {v0, v1, v2, v3, v4}, [Laz/h;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Laz/h;->j:[Laz/h;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Laz/h;->k:Lsx0/b;

    .line 72
    .line 73
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Laz/h;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Laz/h;
    .locals 1

    .line 1
    const-class v0, Laz/h;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Laz/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Laz/h;
    .locals 1

    .line 1
    sget-object v0, Laz/h;->j:[Laz/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Laz/h;

    .line 8
    .line 9
    return-object v0
.end method
