.class public final synthetic Lcp0/d;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lcp0/d;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lcp0/d;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;)Lcz/skodaauto/myskoda/library/rangeice/model/RangeIceStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Lcp0/r;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcp0/d;->d:Lcp0/d;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getPrimaryEngineRange()Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 v0, 0x0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;->getEngineType()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move-object p0, v0

    .line 21
    :goto_0
    invoke-static {p0}, Lcp0/r;->d(Ljava/lang/String;)Lfp0/c;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-eqz p0, :cond_3

    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    if-eq p0, v1, :cond_2

    .line 33
    .line 34
    const/4 v1, 0x3

    .line 35
    if-eq p0, v1, :cond_1

    .line 36
    .line 37
    sget-object p0, Lfp0/a;->h:Lfp0/a;

    .line 38
    .line 39
    :goto_1
    move-object v2, p0

    .line 40
    goto :goto_3

    .line 41
    :cond_1
    sget-object p0, Lfp0/a;->d:Lfp0/a;

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    sget-object p0, Lfp0/a;->e:Lfp0/a;

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_3
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getSecondaryEngineRange()Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-eqz p0, :cond_4

    .line 52
    .line 53
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;->getEngineType()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    goto :goto_2

    .line 58
    :cond_4
    move-object p0, v0

    .line 59
    :goto_2
    invoke-static {p0}, Lcp0/r;->d(Ljava/lang/String;)Lfp0/c;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    sget-object v1, Lfp0/c;->f:Lfp0/c;

    .line 64
    .line 65
    if-ne p0, v1, :cond_5

    .line 66
    .line 67
    sget-object p0, Lfp0/a;->g:Lfp0/a;

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_5
    sget-object p0, Lfp0/a;->f:Lfp0/a;

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :goto_3
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getPrimaryEngineRange()Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    if-eqz p0, :cond_6

    .line 78
    .line 79
    invoke-static {p0}, Lcp0/r;->e(Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;)Lfp0/b;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    :goto_4
    move-object v4, p0

    .line 84
    goto :goto_5

    .line 85
    :cond_6
    new-instance p0, Lfp0/b;

    .line 86
    .line 87
    sget-object v1, Lfp0/c;->h:Lfp0/c;

    .line 88
    .line 89
    invoke-direct {p0, v1, v0, v0, v0}, Lfp0/b;-><init>(Lfp0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lqr0/d;)V

    .line 90
    .line 91
    .line 92
    goto :goto_4

    .line 93
    :goto_5
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getSecondaryEngineRange()Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    if-eqz p0, :cond_7

    .line 98
    .line 99
    invoke-static {p0}, Lcp0/r;->e(Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;)Lfp0/b;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    move-object v5, p0

    .line 104
    goto :goto_6

    .line 105
    :cond_7
    move-object v5, v0

    .line 106
    :goto_6
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getAdBlueRange()Ljava/math/BigDecimal;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    const-wide v6, 0x408f400000000000L    # 1000.0

    .line 111
    .line 112
    .line 113
    .line 114
    .line 115
    if-eqz p0, :cond_8

    .line 116
    .line 117
    invoke-static {p0}, Lcp0/r;->c(Ljava/math/BigDecimal;)Ljava/lang/Integer;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-eqz p0, :cond_8

    .line 122
    .line 123
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    int-to-double v8, p0

    .line 128
    mul-double/2addr v8, v6

    .line 129
    new-instance p0, Lqr0/d;

    .line 130
    .line 131
    invoke-direct {p0, v8, v9}, Lqr0/d;-><init>(D)V

    .line 132
    .line 133
    .line 134
    move-object v3, p0

    .line 135
    goto :goto_7

    .line 136
    :cond_8
    move-object v3, v0

    .line 137
    :goto_7
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getTotalRangeInKm()Ljava/math/BigDecimal;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    if-eqz p0, :cond_9

    .line 142
    .line 143
    invoke-static {p0}, Lcp0/r;->c(Ljava/math/BigDecimal;)Ljava/lang/Integer;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    if-eqz p0, :cond_9

    .line 148
    .line 149
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 150
    .line 151
    .line 152
    move-result p0

    .line 153
    int-to-double v0, p0

    .line 154
    mul-double/2addr v0, v6

    .line 155
    new-instance p0, Lqr0/d;

    .line 156
    .line 157
    invoke-direct {p0, v0, v1}, Lqr0/d;-><init>(D)V

    .line 158
    .line 159
    .line 160
    move-object v6, p0

    .line 161
    goto :goto_8

    .line 162
    :cond_9
    move-object v6, v0

    .line 163
    :goto_8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 164
    .line 165
    .line 166
    move-result-object v7

    .line 167
    new-instance v1, Lfp0/e;

    .line 168
    .line 169
    invoke-direct/range {v1 .. v7}, Lfp0/e;-><init>(Lfp0/a;Lqr0/d;Lfp0/b;Lfp0/b;Lqr0/d;Ljava/time/OffsetDateTime;)V

    .line 170
    .line 171
    .line 172
    return-object v1
.end method
