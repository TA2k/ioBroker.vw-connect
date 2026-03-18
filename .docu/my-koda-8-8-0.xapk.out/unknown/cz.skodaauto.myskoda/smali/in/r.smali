.class public final enum Lin/r;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lin/r;

.field public static final enum e:Lin/r;

.field public static final enum f:Lin/r;

.field public static final enum g:Lin/r;

.field public static final enum h:Lin/r;

.field public static final enum i:Lin/r;

.field public static final enum j:Lin/r;

.field public static final enum k:Lin/r;

.field public static final enum l:Lin/r;

.field public static final enum m:Lin/r;

.field public static final synthetic n:[Lin/r;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Lin/r;

    .line 2
    .line 3
    const-string v1, "none"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lin/r;->d:Lin/r;

    .line 10
    .line 11
    new-instance v1, Lin/r;

    .line 12
    .line 13
    const-string v2, "xMinYMin"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lin/r;->e:Lin/r;

    .line 20
    .line 21
    new-instance v2, Lin/r;

    .line 22
    .line 23
    const-string v3, "xMidYMin"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lin/r;->f:Lin/r;

    .line 30
    .line 31
    new-instance v3, Lin/r;

    .line 32
    .line 33
    const-string v4, "xMaxYMin"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lin/r;->g:Lin/r;

    .line 40
    .line 41
    new-instance v4, Lin/r;

    .line 42
    .line 43
    const-string v5, "xMinYMid"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Lin/r;->h:Lin/r;

    .line 50
    .line 51
    new-instance v5, Lin/r;

    .line 52
    .line 53
    const-string v6, "xMidYMid"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Lin/r;->i:Lin/r;

    .line 60
    .line 61
    new-instance v6, Lin/r;

    .line 62
    .line 63
    const-string v7, "xMaxYMid"

    .line 64
    .line 65
    const/4 v8, 0x6

    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v6, Lin/r;->j:Lin/r;

    .line 70
    .line 71
    new-instance v7, Lin/r;

    .line 72
    .line 73
    const-string v8, "xMinYMax"

    .line 74
    .line 75
    const/4 v9, 0x7

    .line 76
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v7, Lin/r;->k:Lin/r;

    .line 80
    .line 81
    new-instance v8, Lin/r;

    .line 82
    .line 83
    const-string v9, "xMidYMax"

    .line 84
    .line 85
    const/16 v10, 0x8

    .line 86
    .line 87
    invoke-direct {v8, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    sput-object v8, Lin/r;->l:Lin/r;

    .line 91
    .line 92
    new-instance v9, Lin/r;

    .line 93
    .line 94
    const-string v10, "xMaxYMax"

    .line 95
    .line 96
    const/16 v11, 0x9

    .line 97
    .line 98
    invoke-direct {v9, v10, v11}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    sput-object v9, Lin/r;->m:Lin/r;

    .line 102
    .line 103
    filled-new-array/range {v0 .. v9}, [Lin/r;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    sput-object v0, Lin/r;->n:[Lin/r;

    .line 108
    .line 109
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lin/r;
    .locals 1

    .line 1
    const-class v0, Lin/r;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lin/r;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lin/r;
    .locals 1

    .line 1
    sget-object v0, Lin/r;->n:[Lin/r;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lin/r;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lin/r;

    .line 8
    .line 9
    return-object v0
.end method
