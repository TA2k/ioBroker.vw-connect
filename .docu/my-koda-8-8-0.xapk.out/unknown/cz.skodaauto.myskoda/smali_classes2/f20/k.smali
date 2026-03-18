.class public final enum Lf20/k;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic g:[Lf20/k;

.field public static final synthetic h:Lsx0/b;


# instance fields
.field public final d:I

.field public final e:I

.field public final f:I


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Lf20/k;

    .line 2
    .line 3
    const v4, 0x7f12027c

    .line 4
    .line 5
    .line 6
    const v5, 0x7f12027b

    .line 7
    .line 8
    .line 9
    const-string v1, "Braking"

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const v3, 0x7f0800f1

    .line 13
    .line 14
    .line 15
    invoke-direct/range {v0 .. v5}, Lf20/k;-><init>(Ljava/lang/String;IIII)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Lf20/k;

    .line 19
    .line 20
    const v5, 0x7f120284

    .line 21
    .line 22
    .line 23
    const v6, 0x7f120283

    .line 24
    .line 25
    .line 26
    const-string v2, "Speeding"

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    const v4, 0x7f0800f5

    .line 30
    .line 31
    .line 32
    invoke-direct/range {v1 .. v6}, Lf20/k;-><init>(Ljava/lang/String;IIII)V

    .line 33
    .line 34
    .line 35
    new-instance v2, Lf20/k;

    .line 36
    .line 37
    const v6, 0x7f12027a

    .line 38
    .line 39
    .line 40
    const v7, 0x7f120279

    .line 41
    .line 42
    .line 43
    const-string v3, "Acceleration"

    .line 44
    .line 45
    const/4 v4, 0x2

    .line 46
    const v5, 0x7f0800f0

    .line 47
    .line 48
    .line 49
    invoke-direct/range {v2 .. v7}, Lf20/k;-><init>(Ljava/lang/String;IIII)V

    .line 50
    .line 51
    .line 52
    new-instance v3, Lf20/k;

    .line 53
    .line 54
    const v7, 0x7f120280

    .line 55
    .line 56
    .line 57
    const v8, 0x7f12027f

    .line 58
    .line 59
    .line 60
    const-string v4, "EnergyLevel"

    .line 61
    .line 62
    const/4 v5, 0x3

    .line 63
    const v6, 0x7f0800f3

    .line 64
    .line 65
    .line 66
    invoke-direct/range {v3 .. v8}, Lf20/k;-><init>(Ljava/lang/String;IIII)V

    .line 67
    .line 68
    .line 69
    new-instance v4, Lf20/k;

    .line 70
    .line 71
    const v8, 0x7f120282

    .line 72
    .line 73
    .line 74
    const v9, 0x7f120281

    .line 75
    .line 76
    .line 77
    const-string v5, "NightDriving"

    .line 78
    .line 79
    const/4 v6, 0x4

    .line 80
    const v7, 0x7f0800f4

    .line 81
    .line 82
    .line 83
    invoke-direct/range {v4 .. v9}, Lf20/k;-><init>(Ljava/lang/String;IIII)V

    .line 84
    .line 85
    .line 86
    new-instance v5, Lf20/k;

    .line 87
    .line 88
    const v9, 0x7f12027e

    .line 89
    .line 90
    .line 91
    const v10, 0x7f12027d

    .line 92
    .line 93
    .line 94
    const-string v6, "ExcessiveTrip"

    .line 95
    .line 96
    const/4 v7, 0x5

    .line 97
    const v8, 0x7f0800f2

    .line 98
    .line 99
    .line 100
    invoke-direct/range {v5 .. v10}, Lf20/k;-><init>(Ljava/lang/String;IIII)V

    .line 101
    .line 102
    .line 103
    filled-new-array/range {v0 .. v5}, [Lf20/k;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    sput-object v0, Lf20/k;->g:[Lf20/k;

    .line 108
    .line 109
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    sput-object v0, Lf20/k;->h:Lsx0/b;

    .line 114
    .line 115
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IIII)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lf20/k;->d:I

    .line 5
    .line 6
    iput p4, p0, Lf20/k;->e:I

    .line 7
    .line 8
    iput p5, p0, Lf20/k;->f:I

    .line 9
    .line 10
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lf20/k;
    .locals 1

    .line 1
    const-class v0, Lf20/k;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lf20/k;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lf20/k;
    .locals 1

    .line 1
    sget-object v0, Lf20/k;->g:[Lf20/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lf20/k;

    .line 8
    .line 9
    return-object v0
.end method
