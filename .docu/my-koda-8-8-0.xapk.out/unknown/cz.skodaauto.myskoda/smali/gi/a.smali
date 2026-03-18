.class public final enum Lgi/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lgi/a;

.field public static final enum e:Lgi/a;

.field public static final synthetic f:[Lgi/a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lgi/a;

    .line 2
    .line 3
    const-string v1, "Http"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lgi/a;->d:Lgi/a;

    .line 10
    .line 11
    new-instance v1, Lgi/a;

    .line 12
    .line 13
    const-string v2, "Bff"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lgi/a;

    .line 20
    .line 21
    const-string v3, "Kitten"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lgi/a;->e:Lgi/a;

    .line 28
    .line 29
    new-instance v3, Lgi/a;

    .line 30
    .line 31
    const-string v4, "DI"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    filled-new-array {v0, v1, v2, v3}, [Lgi/a;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lgi/a;->f:[Lgi/a;

    .line 42
    .line 43
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lgi/a;
    .locals 1

    .line 1
    const-class v0, Lgi/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lgi/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lgi/a;
    .locals 1

    .line 1
    sget-object v0, Lgi/a;->f:[Lgi/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lgi/a;

    .line 8
    .line 9
    return-object v0
.end method
