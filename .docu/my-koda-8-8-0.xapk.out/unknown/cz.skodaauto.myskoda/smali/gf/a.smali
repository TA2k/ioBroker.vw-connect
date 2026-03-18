.class public final enum Lgf/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lgf/a;

.field public static final synthetic e:[Lgf/a;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lgf/a;

    .line 2
    .line 3
    const-string v1, "ONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lgf/a;

    .line 10
    .line 11
    const-string v2, "TWO"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lgf/a;

    .line 18
    .line 19
    const-string v3, "THREE"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lgf/a;

    .line 26
    .line 27
    const-string v4, "FOUR"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Lgf/a;

    .line 34
    .line 35
    const-string v5, "None"

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    sput-object v4, Lgf/a;->d:Lgf/a;

    .line 42
    .line 43
    filled-new-array {v0, v1, v2, v3, v4}, [Lgf/a;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lgf/a;->e:[Lgf/a;

    .line 48
    .line 49
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lgf/a;
    .locals 1

    .line 1
    const-class v0, Lgf/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lgf/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lgf/a;
    .locals 1

    .line 1
    sget-object v0, Lgf/a;->e:[Lgf/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lgf/a;

    .line 8
    .line 9
    return-object v0
.end method
