.class public final enum Li31/w;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Li31/w;

.field public static final enum f:Li31/w;

.field public static final enum g:Li31/w;

.field public static final enum h:Li31/w;

.field public static final synthetic i:[Li31/w;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Li31/w;

    .line 2
    .line 3
    const-string v1, "Red"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Li31/w;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Li31/w;->e:Li31/w;

    .line 10
    .line 11
    new-instance v1, Li31/w;

    .line 12
    .line 13
    const-string v2, "Yellow"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3, v3}, Li31/w;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Li31/w;->f:Li31/w;

    .line 20
    .line 21
    new-instance v2, Li31/w;

    .line 22
    .line 23
    const-string v3, "White"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4, v4}, Li31/w;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    new-instance v3, Li31/w;

    .line 30
    .line 31
    const-string v4, "Green"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5, v5}, Li31/w;-><init>(Ljava/lang/String;II)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Li31/w;->g:Li31/w;

    .line 38
    .line 39
    new-instance v4, Li31/w;

    .line 40
    .line 41
    const-string v5, "Other"

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    invoke-direct {v4, v5, v6, v6}, Li31/w;-><init>(Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    sput-object v4, Li31/w;->h:Li31/w;

    .line 48
    .line 49
    filled-new-array {v0, v1, v2, v3, v4}, [Li31/w;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Li31/w;->i:[Li31/w;

    .line 54
    .line 55
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Li31/w;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Li31/w;
    .locals 1

    .line 1
    const-class v0, Li31/w;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li31/w;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Li31/w;
    .locals 1

    .line 1
    sget-object v0, Li31/w;->i:[Li31/w;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Li31/w;

    .line 8
    .line 9
    return-object v0
.end method
