.class public final enum Lt01/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lt01/a;

.field public static final enum e:Lt01/a;

.field public static final enum f:Lt01/a;

.field public static final synthetic g:[Lt01/a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lt01/a;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lt01/a;->d:Lt01/a;

    .line 10
    .line 11
    new-instance v1, Lt01/a;

    .line 12
    .line 13
    const-string v2, "BASIC"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lt01/a;

    .line 20
    .line 21
    const-string v3, "HEADERS"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lt01/a;->e:Lt01/a;

    .line 28
    .line 29
    new-instance v3, Lt01/a;

    .line 30
    .line 31
    const-string v4, "BODY"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Lt01/a;->f:Lt01/a;

    .line 38
    .line 39
    filled-new-array {v0, v1, v2, v3}, [Lt01/a;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lt01/a;->g:[Lt01/a;

    .line 44
    .line 45
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lt01/a;
    .locals 1

    .line 1
    const-class v0, Lt01/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt01/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lt01/a;
    .locals 1

    .line 1
    sget-object v0, Lt01/a;->g:[Lt01/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lt01/a;

    .line 8
    .line 9
    return-object v0
.end method
