.class public final synthetic Lh50/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lh50/p;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lh50/p;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    packed-switch p0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    invoke-static {}, Lcz/myskoda/api/vas/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :pswitch_0
    invoke-static {}, Lcz/myskoda/api/vas/infrastructure/ApiClient;->e()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_1
    sget-object p0, Lhw/c;->a:Ll2/u2;

    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_2
    sget-object p0, Lhl/a;->a:Ll2/u2;

    .line 23
    .line 24
    return-object v0

    .line 25
    :pswitch_3
    const-string p0, "Unable to start ShakeDetector. SensorManager is not available."

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_4
    sget-object p0, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 29
    .line 30
    const-string p0, "Device location updates stopped."

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_5
    sget-object p0, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 34
    .line 35
    const-string p0, "Can\'t start device location updates because location permission is not granted."

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_6
    sget-object p0, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 39
    .line 40
    const-string p0, "Requesting device location updates."

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_7
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :pswitch_8
    sget-object p0, Lha0/b;->a:Lc1/a2;

    .line 53
    .line 54
    return-object v1

    .line 55
    :pswitch_9
    sget-object p0, Lh91/e;->a:Lh91/e;

    .line 56
    .line 57
    const-string p0, "post(): Failed to post runnable on set worker. -> Post runnable main thread handler."

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string v0, "No RpaSpacings provided!"

    .line 63
    .line 64
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :pswitch_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string v0, "No RpaImages provided!"

    .line 71
    .line 72
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :pswitch_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string v0, "No RpaIcons provided!"

    .line 79
    .line 80
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :pswitch_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    const-string v0, "No RpaDimensions provided!"

    .line 87
    .line 88
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :pswitch_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    const-string v0, "No RpaColorScheme provided!"

    .line 95
    .line 96
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :pswitch_f
    const-string p0, "showQRCodeScanningScreen()"

    .line 101
    .line 102
    return-object p0

    .line 103
    :pswitch_10
    const-string p0, "showPairingCancelledScreen()"

    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_11
    const-string p0, "showPairingInProgressScreen()"

    .line 107
    .line 108
    return-object p0

    .line 109
    :pswitch_12
    const-string p0, "RPA stopScanningForVehicles()"

    .line 110
    .line 111
    return-object p0

    .line 112
    :pswitch_13
    const-string p0, "RPA startScanningForVehicles()"

    .line 113
    .line 114
    return-object p0

    .line 115
    :pswitch_14
    sget-object p0, Lh70/m;->a:Ll2/j1;

    .line 116
    .line 117
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Lg61/e;

    .line 122
    .line 123
    if-eqz p0, :cond_0

    .line 124
    .line 125
    invoke-interface {p0}, Lg61/e;->C()V

    .line 126
    .line 127
    .line 128
    :cond_0
    return-object v1

    .line 129
    :pswitch_15
    sget-object p0, Lh70/m;->a:Ll2/j1;

    .line 130
    .line 131
    return-object v1

    .line 132
    :pswitch_16
    sget-object p0, Lh60/f;->a:Llx0/l;

    .line 133
    .line 134
    return-object v1

    .line 135
    :pswitch_17
    sget-object p0, Lg50/a;->a:Lg50/a;

    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_18
    new-instance p0, Llj0/a;

    .line 139
    .line 140
    const-string v0, "ai_trip_plan_btn_edit_trip"

    .line 141
    .line 142
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    return-object p0

    .line 146
    :pswitch_19
    new-instance p0, Llj0/a;

    .line 147
    .line 148
    const-string v0, "route_adjustment"

    .line 149
    .line 150
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    return-object p0

    .line 154
    :pswitch_1a
    new-instance p0, Llj0/a;

    .line 155
    .line 156
    const-string v0, "share_route"

    .line 157
    .line 158
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    return-object p0

    .line 162
    :pswitch_1b
    new-instance p0, Llj0/a;

    .line 163
    .line 164
    const-string v0, "maps_route_button_poi_detail"

    .line 165
    .line 166
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    return-object p0

    .line 170
    :pswitch_1c
    new-instance p0, Llj0/a;

    .line 171
    .line 172
    const-string v0, "discard_route_cancelled"

    .line 173
    .line 174
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    return-object p0

    .line 178
    nop

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
