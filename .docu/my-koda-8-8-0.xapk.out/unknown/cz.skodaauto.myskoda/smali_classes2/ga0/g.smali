.class public final enum Lga0/g;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lga0/g;

.field public static final enum e:Lga0/g;

.field public static final enum f:Lga0/g;

.field public static final enum g:Lga0/g;

.field public static final synthetic h:[Lga0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lga0/g;

    .line 2
    .line 3
    const-string v1, "PlayProtection"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lga0/g;

    .line 10
    .line 11
    const-string v2, "Windows"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lga0/g;->d:Lga0/g;

    .line 18
    .line 19
    new-instance v2, Lga0/g;

    .line 20
    .line 21
    const-string v3, "Sunroof"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lga0/g;->e:Lga0/g;

    .line 28
    .line 29
    new-instance v3, Lga0/g;

    .line 30
    .line 31
    const-string v4, "ParkingLights"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Lga0/g;->f:Lga0/g;

    .line 38
    .line 39
    new-instance v4, Lga0/g;

    .line 40
    .line 41
    const-string v5, "Bonnet"

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    sput-object v4, Lga0/g;->g:Lga0/g;

    .line 48
    .line 49
    filled-new-array {v0, v1, v2, v3, v4}, [Lga0/g;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lga0/g;->h:[Lga0/g;

    .line 54
    .line 55
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lga0/g;
    .locals 1

    .line 1
    const-class v0, Lga0/g;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lga0/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lga0/g;
    .locals 1

    .line 1
    sget-object v0, Lga0/g;->h:[Lga0/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lga0/g;

    .line 8
    .line 9
    return-object v0
.end method
