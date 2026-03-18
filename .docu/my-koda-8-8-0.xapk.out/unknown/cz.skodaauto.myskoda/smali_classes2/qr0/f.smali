.class public final enum Lqr0/f;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqr0/m;


# static fields
.field public static final enum d:Lqr0/f;

.field public static final enum e:Lqr0/f;

.field public static final enum f:Lqr0/f;

.field public static final enum g:Lqr0/f;

.field public static final enum h:Lqr0/f;

.field public static final enum i:Lqr0/f;

.field public static final enum j:Lqr0/f;

.field public static final enum k:Lqr0/f;

.field public static final synthetic l:[Lqr0/f;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Lqr0/f;

    .line 2
    .line 3
    const-string v1, "Foot"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lqr0/f;->d:Lqr0/f;

    .line 10
    .line 11
    new-instance v1, Lqr0/f;

    .line 12
    .line 13
    const-string v2, "Kilometer"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lqr0/f;->e:Lqr0/f;

    .line 20
    .line 21
    new-instance v2, Lqr0/f;

    .line 22
    .line 23
    const-string v3, "KilometerPerHour"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lqr0/f;->f:Lqr0/f;

    .line 30
    .line 31
    new-instance v3, Lqr0/f;

    .line 32
    .line 33
    const-string v4, "Meter"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lqr0/f;->g:Lqr0/f;

    .line 40
    .line 41
    new-instance v4, Lqr0/f;

    .line 42
    .line 43
    const-string v5, "Mile"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Lqr0/f;->h:Lqr0/f;

    .line 50
    .line 51
    new-instance v5, Lqr0/f;

    .line 52
    .line 53
    const-string v6, "MilePerGallon"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Lqr0/f;->i:Lqr0/f;

    .line 60
    .line 61
    new-instance v6, Lqr0/f;

    .line 62
    .line 63
    const-string v7, "MilePerHour"

    .line 64
    .line 65
    const/4 v8, 0x6

    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v6, Lqr0/f;->j:Lqr0/f;

    .line 70
    .line 71
    new-instance v7, Lqr0/f;

    .line 72
    .line 73
    const-string v8, "MilePerKilowattHour"

    .line 74
    .line 75
    const/4 v9, 0x7

    .line 76
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v7, Lqr0/f;->k:Lqr0/f;

    .line 80
    .line 81
    filled-new-array/range {v0 .. v7}, [Lqr0/f;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    sput-object v0, Lqr0/f;->l:[Lqr0/f;

    .line 86
    .line 87
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 88
    .line 89
    .line 90
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqr0/f;
    .locals 1

    .line 1
    const-class v0, Lqr0/f;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqr0/f;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqr0/f;
    .locals 1

    .line 1
    sget-object v0, Lqr0/f;->l:[Lqr0/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqr0/f;

    .line 8
    .line 9
    return-object v0
.end method
