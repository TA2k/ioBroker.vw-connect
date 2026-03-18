.class public final enum Lg40/n;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lfv/b;

.field public static final enum f:Lg40/n;

.field public static final synthetic g:[Lg40/n;

.field public static final synthetic h:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lg40/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "achievement"

    .line 5
    .line 6
    const-string v3, "Achievement"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lg40/n;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lg40/n;->f:Lg40/n;

    .line 12
    .line 13
    new-instance v1, Lg40/n;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "promo"

    .line 17
    .line 18
    const-string v4, "Promo"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lg40/n;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    filled-new-array {v0, v1}, [Lg40/n;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Lg40/n;->g:[Lg40/n;

    .line 28
    .line 29
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lg40/n;->h:Lsx0/b;

    .line 34
    .line 35
    new-instance v0, Lfv/b;

    .line 36
    .line 37
    const/4 v1, 0x6

    .line 38
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lg40/n;->e:Lfv/b;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lg40/n;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lg40/n;
    .locals 1

    .line 1
    const-class v0, Lg40/n;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lg40/n;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lg40/n;
    .locals 1

    .line 1
    sget-object v0, Lg40/n;->g:[Lg40/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lg40/n;

    .line 8
    .line 9
    return-object v0
.end method
