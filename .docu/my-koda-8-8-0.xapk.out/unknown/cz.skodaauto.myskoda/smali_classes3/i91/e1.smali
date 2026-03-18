.class public final enum Li91/e1;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Li91/e1;

.field public static final enum e:Li91/e1;

.field public static final synthetic f:[Li91/e1;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Li91/e1;

    .line 2
    .line 3
    const-string v1, "Info"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Li91/e1;

    .line 10
    .line 11
    const-string v2, "Positive"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Li91/e1;

    .line 18
    .line 19
    const-string v3, "Warning"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    sput-object v2, Li91/e1;->d:Li91/e1;

    .line 26
    .line 27
    new-instance v3, Li91/e1;

    .line 28
    .line 29
    const-string v4, "Alert"

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    new-instance v4, Li91/e1;

    .line 36
    .line 37
    const-string v5, "Neutral"

    .line 38
    .line 39
    const/4 v6, 0x4

    .line 40
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    sput-object v4, Li91/e1;->e:Li91/e1;

    .line 44
    .line 45
    filled-new-array {v0, v1, v2, v3, v4}, [Li91/e1;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sput-object v0, Li91/e1;->f:[Li91/e1;

    .line 50
    .line 51
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Li91/e1;
    .locals 1

    .line 1
    const-class v0, Li91/e1;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li91/e1;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Li91/e1;
    .locals 1

    .line 1
    sget-object v0, Li91/e1;->f:[Li91/e1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Li91/e1;

    .line 8
    .line 9
    return-object v0
.end method
