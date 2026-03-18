.class public final enum Lds0/d;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lds0/d;

.field public static final enum e:Lds0/d;

.field public static final enum f:Lds0/d;

.field public static final synthetic g:[Lds0/d;

.field public static final synthetic h:Lsx0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lds0/d;

    .line 2
    .line 3
    const-string v1, "Automatic"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lds0/d;->d:Lds0/d;

    .line 10
    .line 11
    new-instance v1, Lds0/d;

    .line 12
    .line 13
    const-string v2, "Light"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lds0/d;->e:Lds0/d;

    .line 20
    .line 21
    new-instance v2, Lds0/d;

    .line 22
    .line 23
    const-string v3, "Dark"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lds0/d;->f:Lds0/d;

    .line 30
    .line 31
    filled-new-array {v0, v1, v2}, [Lds0/d;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lds0/d;->g:[Lds0/d;

    .line 36
    .line 37
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lds0/d;->h:Lsx0/b;

    .line 42
    .line 43
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lds0/d;
    .locals 1

    .line 1
    const-class v0, Lds0/d;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lds0/d;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lds0/d;
    .locals 1

    .line 1
    sget-object v0, Lds0/d;->g:[Lds0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lds0/d;

    .line 8
    .line 9
    return-object v0
.end method
