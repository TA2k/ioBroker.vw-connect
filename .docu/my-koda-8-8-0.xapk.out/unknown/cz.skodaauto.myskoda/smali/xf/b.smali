.class public final synthetic Lxf/b;
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
    iput p1, p0, Lxf/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lql0/g;)V
    .locals 0

    .line 2
    const/16 p1, 0x16

    iput p1, p0, Lxf/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lxf/b;->d:I

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
    sget-object p0, La40/b;->c:La40/b;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_0
    const-string p0, "There is no userId for crashlytics in database"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_1
    sget p0, Lz20/d;->a:F

    .line 16
    .line 17
    return-object v1

    .line 18
    :pswitch_2
    new-instance p0, Llj0/a;

    .line 19
    .line 20
    const-string v0, "DN: Video PLAY/PAUSE"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_3
    invoke-static {}, Lcz/myskoda/api/bff_maps/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_4
    invoke-static {}, Lcz/myskoda/api/bff_maps/v2/infrastructure/ApiClient;->a()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_5
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_6
    return-object v1

    .line 44
    :pswitch_7
    sget-object p0, Lx70/c;->c:Lx70/c;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_8
    sget-object p0, Lx70/c;->b:Lx70/c;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v0, "No translator provided"

    .line 53
    .line 54
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :pswitch_a
    const-string p0, "awaitClose called"

    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_b
    new-instance p0, Lr51/a;

    .line 62
    .line 63
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 64
    .line 65
    .line 66
    const-class v0, Lr51/a;

    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    const-string v1, "keystore:"

    .line 73
    .line 74
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    new-instance v0, Lqf0/d;

    .line 78
    .line 79
    const/4 v1, 0x4

    .line 80
    invoke-direct {v0, v1}, Lqf0/d;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 84
    .line 85
    .line 86
    new-instance v0, Lqf0/d;

    .line 87
    .line 88
    const/4 v1, 0x5

    .line 89
    invoke-direct {v0, v1}, Lqf0/d;-><init>(I)V

    .line 90
    .line 91
    .line 92
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 93
    .line 94
    .line 95
    return-object p0

    .line 96
    :pswitch_c
    new-instance p0, Llj0/a;

    .line 97
    .line 98
    const-string v0, "garage_car_configurator_card_title"

    .line 99
    .line 100
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_d
    new-instance p0, Llj0/a;

    .line 105
    .line 106
    const-string v0, "garage_car_configurator_tile_explore_more"

    .line 107
    .line 108
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    return-object p0

    .line 112
    :pswitch_e
    new-instance p0, Llj0/a;

    .line 113
    .line 114
    const-string v0, "discover_news_cars_tab_configurator_button"

    .line 115
    .line 116
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    return-object p0

    .line 120
    :pswitch_f
    invoke-static {}, Lcz/myskoda/api/bff_manuals/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_10
    invoke-static {}, Lcz/myskoda/api/bff_manuals/v2/infrastructure/ApiClient;->a()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    :pswitch_11
    const-string p0, "io.ktor.util.date.Month"

    .line 131
    .line 132
    invoke-static {}, Lxw0/e;->values()[Lxw0/e;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0

    .line 141
    :pswitch_12
    const-string p0, "io.ktor.util.date.WeekDay"

    .line 142
    .line 143
    invoke-static {}, Lxw0/f;->values()[Lxw0/f;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :pswitch_13
    sget-object p0, Lxk0/i0;->a:Lwk0/x1;

    .line 153
    .line 154
    return-object v1

    .line 155
    :pswitch_14
    const-string p0, "Unable to set WindowManager.LayoutParams.FLAG_SECURE because no Activity found."

    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_15
    sget p0, Lxf0/r0;->a:F

    .line 159
    .line 160
    return-object v1

    .line 161
    :pswitch_16
    const-string p0, "Unable to set Activity.requestedOrientation because no Activity found."

    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_17
    sget-object p0, Lxf0/q;->a:Lgy0/j;

    .line 165
    .line 166
    return-object v1

    .line 167
    :pswitch_18
    sget-object p0, Lxf0/m;->a:Lgy0/j;

    .line 168
    .line 169
    return-object v1

    .line 170
    :pswitch_19
    invoke-static {}, Lxf/j;->values()[Lxf/j;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    const-string v1, "INACTIVE_SHOW_VEHICLE_POPUP"

    .line 175
    .line 176
    const-string v2, "INACTIVE_DONT_SHOW_POPUP"

    .line 177
    .line 178
    const-string v3, "SHOW_UPSELL"

    .line 179
    .line 180
    filled-new-array {v3, v1, v2}, [Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    filled-new-array {v0, v0, v0}, [[Ljava/lang/annotation/Annotation;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    const-string v2, "cariad.charging.multicharge.kitten.plugandchargeoffline.models.PNCOfflineGetResponse.PlugAndChargeOfflineOverviewList.AudiState"

    .line 189
    .line 190
    invoke-static {v2, p0, v1, v0}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    return-object p0

    .line 195
    :pswitch_1a
    sget-object p0, Lxf/j;->Companion:Lxf/i;

    .line 196
    .line 197
    invoke-virtual {p0}, Lxf/i;->serializer()Lqz0/a;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    return-object p0

    .line 202
    :pswitch_1b
    invoke-static {}, Lxf/f;->values()[Lxf/f;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    const-string v1, "ACTIVE"

    .line 207
    .line 208
    const-string v2, "LOADING"

    .line 209
    .line 210
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    filled-new-array {v0, v0}, [[Ljava/lang/annotation/Annotation;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    const-string v2, "cariad.charging.multicharge.kitten.plugandchargeoffline.models.PNCOfflineGetResponse.PlugAndChargeOfflineOverviewAudi.ToggleState"

    .line 219
    .line 220
    invoke-static {v2, p0, v1, v0}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    return-object p0

    .line 225
    :pswitch_1c
    sget-object p0, Lxf/f;->Companion:Lxf/e;

    .line 226
    .line 227
    invoke-virtual {p0}, Lxf/e;->serializer()Lqz0/a;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    return-object p0

    .line 232
    nop

    .line 233
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
