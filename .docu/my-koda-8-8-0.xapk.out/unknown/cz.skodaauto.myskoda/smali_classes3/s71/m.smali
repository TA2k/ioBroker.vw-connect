.class public final enum Ls71/m;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Ls71/m;

.field public static final enum e:Ls71/m;

.field public static final enum f:Ls71/m;

.field public static final enum g:Ls71/m;

.field public static final enum h:Ls71/m;

.field public static final enum i:Ls71/m;

.field public static final enum j:Ls71/m;

.field public static final enum k:Ls71/m;

.field public static final enum l:Ls71/m;

.field public static final enum m:Ls71/m;

.field public static final synthetic n:[Ls71/m;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Ls71/m;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ls71/m;->d:Ls71/m;

    .line 10
    .line 11
    new-instance v1, Ls71/m;

    .line 12
    .line 13
    const-string v2, "DRIVE_ACTIVATION_STARTED_WAITING"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Ls71/m;->e:Ls71/m;

    .line 20
    .line 21
    new-instance v2, Ls71/m;

    .line 22
    .line 23
    const-string v3, "STOP_DRIVE_AND_DRIVE_ACTIVATION"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Ls71/m;->f:Ls71/m;

    .line 30
    .line 31
    new-instance v3, Ls71/m;

    .line 32
    .line 33
    const-string v4, "STOP_CLOSING_WINDOWS"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Ls71/m;->g:Ls71/m;

    .line 40
    .line 41
    new-instance v4, Ls71/m;

    .line 42
    .line 43
    const-string v5, "DISCONNECT"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Ls71/m;->h:Ls71/m;

    .line 50
    .line 51
    new-instance v5, Ls71/m;

    .line 52
    .line 53
    const-string v6, "DISCONNECT_WITH_PREVIOUS_FUNCTION_STOP"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Ls71/m;->i:Ls71/m;

    .line 60
    .line 61
    new-instance v6, Ls71/m;

    .line 62
    .line 63
    const-string v7, "INTERNAL_MOTOR_TIMEOUT"

    .line 64
    .line 65
    const/4 v8, 0x6

    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v6, Ls71/m;->j:Ls71/m;

    .line 70
    .line 71
    new-instance v7, Ls71/m;

    .line 72
    .line 73
    const-string v8, "INTERNAL_TOUCH_DIAGNOSIS_TIMEOUT"

    .line 74
    .line 75
    const/4 v9, 0x7

    .line 76
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v7, Ls71/m;->k:Ls71/m;

    .line 80
    .line 81
    new-instance v8, Ls71/m;

    .line 82
    .line 83
    const-string v9, "INTERNAL_DRIVE_ACTIVATION_THRESHOLD_REACHED"

    .line 84
    .line 85
    const/16 v10, 0x8

    .line 86
    .line 87
    invoke-direct {v8, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    sput-object v8, Ls71/m;->l:Ls71/m;

    .line 91
    .line 92
    new-instance v9, Ls71/m;

    .line 93
    .line 94
    const-string v10, "INTERNAL_CONNECTION_ESTABLISHMENT_TIMEOUT"

    .line 95
    .line 96
    const/16 v11, 0x9

    .line 97
    .line 98
    invoke-direct {v9, v10, v11}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    sput-object v9, Ls71/m;->m:Ls71/m;

    .line 102
    .line 103
    filled-new-array/range {v0 .. v9}, [Ls71/m;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    sput-object v0, Ls71/m;->n:[Ls71/m;

    .line 108
    .line 109
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 110
    .line 111
    .line 112
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ls71/m;
    .locals 1

    .line 1
    const-class v0, Ls71/m;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ls71/m;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ls71/m;
    .locals 1

    .line 1
    sget-object v0, Ls71/m;->n:[Ls71/m;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ls71/m;

    .line 8
    .line 9
    return-object v0
.end method
