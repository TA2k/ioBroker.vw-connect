.class public final enum Lx71/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lx71/a;

.field public static final enum e:Lx71/a;

.field public static final synthetic f:[Lx71/a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lx71/a;

    .line 2
    .line 3
    const-string v1, "Intersection"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lx71/a;

    .line 10
    .line 11
    const-string v2, "Union"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lx71/a;->d:Lx71/a;

    .line 18
    .line 19
    new-instance v2, Lx71/a;

    .line 20
    .line 21
    const-string v3, "Difference"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Lx71/a;

    .line 28
    .line 29
    const-string v4, "Xor"

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    sput-object v3, Lx71/a;->e:Lx71/a;

    .line 36
    .line 37
    filled-new-array {v0, v1, v2, v3}, [Lx71/a;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lx71/a;->f:[Lx71/a;

    .line 42
    .line 43
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lx71/a;
    .locals 1

    .line 1
    const-class v0, Lx71/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lx71/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lx71/a;
    .locals 1

    .line 1
    sget-object v0, Lx71/a;->f:[Lx71/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lx71/a;

    .line 8
    .line 9
    return-object v0
.end method
