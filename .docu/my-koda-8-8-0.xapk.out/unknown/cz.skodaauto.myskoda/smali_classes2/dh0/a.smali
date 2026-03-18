.class public final enum Ldh0/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Ldh0/a;

.field public static final enum f:Ldh0/a;

.field public static final enum g:Ldh0/a;

.field public static final enum h:Ldh0/a;

.field public static final enum i:Ldh0/a;

.field public static final enum j:Ldh0/a;

.field public static final synthetic k:[Ldh0/a;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Ldh0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "cz.skodaauto.myskoda"

    .line 5
    .line 6
    const-string v3, "MySkoda"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Ldh0/a;->e:Ldh0/a;

    .line 12
    .line 13
    new-instance v1, Ldh0/a;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "cz.skodaauto.connect"

    .line 17
    .line 18
    const-string v4, "MySkoda5"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Ldh0/a;

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    const-string v4, "cz.skodaauto.powerpass"

    .line 27
    .line 28
    const-string v5, "Powerpass"

    .line 29
    .line 30
    invoke-direct {v2, v5, v3, v4}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sput-object v2, Ldh0/a;->f:Ldh0/a;

    .line 34
    .line 35
    new-instance v3, Ldh0/a;

    .line 36
    .line 37
    const/4 v4, 0x3

    .line 38
    const-string v5, "com.google.android.apps.maps"

    .line 39
    .line 40
    const-string v6, "GoogleMaps"

    .line 41
    .line 42
    invoke-direct {v3, v6, v4, v5}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sput-object v3, Ldh0/a;->g:Ldh0/a;

    .line 46
    .line 47
    new-instance v4, Ldh0/a;

    .line 48
    .line 49
    const/4 v5, 0x4

    .line 50
    const-string v6, "cz.seznam.mapy"

    .line 51
    .line 52
    const-string v7, "MapyCz"

    .line 53
    .line 54
    invoke-direct {v4, v7, v5, v6}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    sput-object v4, Ldh0/a;->h:Ldh0/a;

    .line 58
    .line 59
    new-instance v5, Ldh0/a;

    .line 60
    .line 61
    const/4 v6, 0x5

    .line 62
    const-string v7, "com.waze"

    .line 63
    .line 64
    const-string v8, "Waze"

    .line 65
    .line 66
    invoke-direct {v5, v8, v6, v7}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 67
    .line 68
    .line 69
    sput-object v5, Ldh0/a;->i:Ldh0/a;

    .line 70
    .line 71
    new-instance v6, Ldh0/a;

    .line 72
    .line 73
    const/4 v7, 0x6

    .line 74
    const-string v8, "com.google.android.apps.walletnfcrel"

    .line 75
    .line 76
    const-string v9, "GoogleWallet"

    .line 77
    .line 78
    invoke-direct {v6, v9, v7, v8}, Ldh0/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    sput-object v6, Ldh0/a;->j:Ldh0/a;

    .line 82
    .line 83
    filled-new-array/range {v0 .. v6}, [Ldh0/a;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    sput-object v0, Ldh0/a;->k:[Ldh0/a;

    .line 88
    .line 89
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 90
    .line 91
    .line 92
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Ldh0/a;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ldh0/a;
    .locals 1

    .line 1
    const-class v0, Ldh0/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ldh0/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ldh0/a;
    .locals 1

    .line 1
    sget-object v0, Ldh0/a;->k:[Ldh0/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ldh0/a;

    .line 8
    .line 9
    return-object v0
.end method
