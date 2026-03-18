.class public final enum Lrd0/f0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lrd0/f0;

.field public static final enum f:Lrd0/f0;

.field public static final enum g:Lrd0/f0;

.field public static final enum h:Lrd0/f0;

.field public static final enum i:Lrd0/f0;

.field public static final enum j:Lrd0/f0;

.field public static final enum k:Lrd0/f0;

.field public static final enum l:Lrd0/f0;

.field public static final enum m:Lrd0/f0;

.field public static final synthetic n:[Lrd0/f0;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    new-instance v0, Lrd0/f0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "start-stop-charging"

    .line 5
    .line 6
    const-string v3, "BatteryCharging"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lrd0/f0;->e:Lrd0/f0;

    .line 12
    .line 13
    new-instance v1, Lrd0/f0;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "update-auto-unlock-plug"

    .line 17
    .line 18
    const-string v4, "CableLock"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Lrd0/f0;->f:Lrd0/f0;

    .line 24
    .line 25
    new-instance v2, Lrd0/f0;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const-string v4, "update-care-mode"

    .line 29
    .line 30
    const-string v5, "CareMode"

    .line 31
    .line 32
    invoke-direct {v2, v5, v3, v4}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Lrd0/f0;->g:Lrd0/f0;

    .line 36
    .line 37
    new-instance v3, Lrd0/f0;

    .line 38
    .line 39
    const/4 v4, 0x3

    .line 40
    const-string v5, "update-charge-limit"

    .line 41
    .line 42
    const-string v6, "ChargeLimit"

    .line 43
    .line 44
    invoke-direct {v3, v6, v4, v5}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v3, Lrd0/f0;->h:Lrd0/f0;

    .line 48
    .line 49
    new-instance v4, Lrd0/f0;

    .line 50
    .line 51
    const/4 v5, 0x4

    .line 52
    const-string v6, "update-charge-mode"

    .line 53
    .line 54
    const-string v7, "ChargeMode"

    .line 55
    .line 56
    invoke-direct {v4, v7, v5, v6}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v4, Lrd0/f0;->i:Lrd0/f0;

    .line 60
    .line 61
    new-instance v5, Lrd0/f0;

    .line 62
    .line 63
    const/4 v6, 0x5

    .line 64
    const-string v7, "create-charging-profile"

    .line 65
    .line 66
    const-string v8, "ChargingProfilesCreate"

    .line 67
    .line 68
    invoke-direct {v5, v8, v6, v7}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    sput-object v5, Lrd0/f0;->j:Lrd0/f0;

    .line 72
    .line 73
    new-instance v6, Lrd0/f0;

    .line 74
    .line 75
    const/4 v7, 0x6

    .line 76
    const-string v8, "delete-charging-profile"

    .line 77
    .line 78
    const-string v9, "ChargingProfilesDelete"

    .line 79
    .line 80
    invoke-direct {v6, v9, v7, v8}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 81
    .line 82
    .line 83
    sput-object v6, Lrd0/f0;->k:Lrd0/f0;

    .line 84
    .line 85
    new-instance v7, Lrd0/f0;

    .line 86
    .line 87
    const/4 v8, 0x7

    .line 88
    const-string v9, "update-charging-profiles"

    .line 89
    .line 90
    const-string v10, "ChargingProfilesUpdate"

    .line 91
    .line 92
    invoke-direct {v7, v10, v8, v9}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    sput-object v7, Lrd0/f0;->l:Lrd0/f0;

    .line 96
    .line 97
    new-instance v8, Lrd0/f0;

    .line 98
    .line 99
    const/16 v9, 0x8

    .line 100
    .line 101
    const-string v10, "update-charging-current"

    .line 102
    .line 103
    const-string v11, "ReducedCurrent"

    .line 104
    .line 105
    invoke-direct {v8, v11, v9, v10}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 106
    .line 107
    .line 108
    sput-object v8, Lrd0/f0;->m:Lrd0/f0;

    .line 109
    .line 110
    new-instance v9, Lrd0/f0;

    .line 111
    .line 112
    const/16 v10, 0x9

    .line 113
    .line 114
    const-string v11, "update-battery-support"

    .line 115
    .line 116
    const-string v12, "UpdateBatterySupport"

    .line 117
    .line 118
    invoke-direct {v9, v12, v10, v11}, Lrd0/f0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 119
    .line 120
    .line 121
    filled-new-array/range {v0 .. v9}, [Lrd0/f0;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    sput-object v0, Lrd0/f0;->n:[Lrd0/f0;

    .line 126
    .line 127
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 128
    .line 129
    .line 130
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lrd0/f0;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lrd0/f0;
    .locals 1

    .line 1
    const-class v0, Lrd0/f0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lrd0/f0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lrd0/f0;
    .locals 1

    .line 1
    sget-object v0, Lrd0/f0;->n:[Lrd0/f0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lrd0/f0;

    .line 8
    .line 9
    return-object v0
.end method
