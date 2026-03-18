.class public abstract Lrp/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lyj/b;Lyj/b;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x62d53f52

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p3

    .line 19
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    and-int/lit8 v1, v0, 0x13

    .line 32
    .line 33
    const/16 v2, 0x12

    .line 34
    .line 35
    if-eq v1, v2, :cond_2

    .line 36
    .line 37
    const/4 v1, 0x1

    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/4 v1, 0x0

    .line 40
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 41
    .line 42
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    invoke-static {p2}, Llp/kb;->c(Ll2/o;)Lvc/b;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    and-int/lit8 v0, v0, 0x7e

    .line 53
    .line 54
    invoke-interface {v1, p0, p1, p2, v0}, Lvc/b;->F0(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 59
    .line 60
    .line 61
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-eqz p2, :cond_4

    .line 66
    .line 67
    new-instance v0, Lxj/l;

    .line 68
    .line 69
    invoke-direct {v0, p0, p1, p3}, Lxj/l;-><init>(Lyj/b;Lyj/b;I)V

    .line 70
    .line 71
    .line 72
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 73
    .line 74
    :cond_4
    return-void
.end method

.method public static final b(Ljava/lang/String;)Lly/b;
    .locals 3

    .line 1
    sget-object v0, Lly/b;->W4:Lsx0/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v1, Landroidx/collection/d1;

    .line 7
    .line 8
    const/4 v2, 0x6

    .line 9
    invoke-direct {v1, v0, v2}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    :cond_0
    invoke-virtual {v1}, Landroidx/collection/d1;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {v1}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    move-object v2, v0

    .line 23
    check-cast v2, Lly/b;

    .line 24
    .line 25
    invoke-virtual {v2}, Lly/b;->invoke()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v2, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    const/4 v0, 0x0

    .line 37
    :goto_0
    check-cast v0, Lly/b;

    .line 38
    .line 39
    return-object v0
.end method

.method public static final c(Lvg0/c;)Lly/b;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Ltu0/a;

    .line 7
    .line 8
    if-nez v0, :cond_4

    .line 9
    .line 10
    instance-of v0, p0, Lvg0/d;

    .line 11
    .line 12
    if-nez v0, :cond_4

    .line 13
    .line 14
    instance-of v0, p0, Lav0/a;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    instance-of v0, p0, Lx20/b;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    sget-object p0, Lly/b;->g0:Lly/b;

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_1
    instance-of v0, p0, Lr90/a;

    .line 27
    .line 28
    if-eqz v0, :cond_2

    .line 29
    .line 30
    sget-object p0, Lly/b;->H3:Lly/b;

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_2
    instance-of v0, p0, Lg00/a;

    .line 34
    .line 35
    if-eqz v0, :cond_3

    .line 36
    .line 37
    sget-object p0, Lly/b;->d3:Lly/b;

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_3
    new-instance v0, Lh50/q0;

    .line 41
    .line 42
    const/16 v1, 0x1a

    .line 43
    .line 44
    invoke-direct {v0, p0, v1}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 45
    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    invoke-static {v1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 49
    .line 50
    .line 51
    return-object v1

    .line 52
    :cond_4
    :goto_0
    sget-object p0, Lly/b;->d:Lly/b;

    .line 53
    .line 54
    return-object p0
.end method

.method public static final d(Ljava/lang/String;)Lly/b;
    .locals 1

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-deeplink-model-Link$-$this$asRouteOrNull$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lhf0/d;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Application:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 11
    .line 12
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_2f

    .line 21
    .line 22
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->DeliveredHome:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 23
    .line 24
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_2f

    .line 33
    .line 34
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->OrderedHome:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 35
    .line 36
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    goto/16 :goto_1

    .line 47
    .line 48
    :cond_0
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ActiveVentilation:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 49
    .line 50
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_1

    .line 59
    .line 60
    sget-object p0, Lly/b;->K:Lly/b;

    .line 61
    .line 62
    return-object p0

    .line 63
    :cond_1
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->AuxiliaryHeater:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 64
    .line 65
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_2

    .line 74
    .line 75
    sget-object p0, Lly/b;->I:Lly/b;

    .line 76
    .line 77
    return-object p0

    .line 78
    :cond_2
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Battery:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 79
    .line 80
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    if-eqz v0, :cond_3

    .line 89
    .line 90
    sget-object p0, Lly/b;->k:Lly/b;

    .line 91
    .line 92
    return-object p0

    .line 93
    :cond_3
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->BatterySettings:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 94
    .line 95
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    if-eqz v0, :cond_4

    .line 104
    .line 105
    sget-object p0, Lly/b;->t:Lly/b;

    .line 106
    .line 107
    return-object p0

    .line 108
    :cond_4
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->GiveFeedback:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 109
    .line 110
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-eqz v0, :cond_5

    .line 119
    .line 120
    sget-object p0, Lly/b;->R:Lly/b;

    .line 121
    .line 122
    return-object p0

    .line 123
    :cond_5
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->CareAndInsurance:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 124
    .line 125
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    if-eqz v0, :cond_6

    .line 134
    .line 135
    sget-object p0, Lly/b;->q3:Lly/b;

    .line 136
    .line 137
    return-object p0

    .line 138
    :cond_6
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ChargingProfiles:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 139
    .line 140
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    if-eqz v0, :cond_7

    .line 149
    .line 150
    sget-object p0, Lly/b;->o:Lly/b;

    .line 151
    .line 152
    return-object p0

    .line 153
    :cond_7
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ClimateControl:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 154
    .line 155
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    if-eqz v0, :cond_8

    .line 164
    .line 165
    sget-object p0, Lly/b;->D:Lly/b;

    .line 166
    .line 167
    return-object p0

    .line 168
    :cond_8
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Congratulations:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 169
    .line 170
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 175
    .line 176
    .line 177
    move-result v0

    .line 178
    if-eqz v0, :cond_9

    .line 179
    .line 180
    sget-object p0, Lly/b;->d3:Lly/b;

    .line 181
    .line 182
    return-object p0

    .line 183
    :cond_9
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ContactInformation:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 184
    .line 185
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    if-eqz v0, :cond_a

    .line 194
    .line 195
    sget-object p0, Lly/b;->M:Lly/b;

    .line 196
    .line 197
    return-object p0

    .line 198
    :cond_a
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ContactUs:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 199
    .line 200
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    if-eqz v0, :cond_b

    .line 209
    .line 210
    sget-object p0, Lly/b;->L:Lly/b;

    .line 211
    .line 212
    return-object p0

    .line 213
    :cond_b
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->DepartureTimers:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 214
    .line 215
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 220
    .line 221
    .line 222
    move-result v0

    .line 223
    if-eqz v0, :cond_c

    .line 224
    .line 225
    sget-object p0, Lly/b;->V:Lly/b;

    .line 226
    .line 227
    return-object p0

    .line 228
    :cond_c
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->DigitalKey:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 229
    .line 230
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 235
    .line 236
    .line 237
    move-result v0

    .line 238
    if-eqz v0, :cond_d

    .line 239
    .line 240
    sget-object p0, Lly/b;->m2:Lly/b;

    .line 241
    .line 242
    return-object p0

    .line 243
    :cond_d
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->EprivacyConsent:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 244
    .line 245
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 250
    .line 251
    .line 252
    move-result v0

    .line 253
    if-eqz v0, :cond_e

    .line 254
    .line 255
    sget-object p0, Lly/b;->z1:Lly/b;

    .line 256
    .line 257
    return-object p0

    .line 258
    :cond_e
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->GuestUserManagement:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 259
    .line 260
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 265
    .line 266
    .line 267
    move-result v0

    .line 268
    if-eqz v0, :cond_f

    .line 269
    .line 270
    sget-object p0, Lly/b;->s1:Lly/b;

    .line 271
    .line 272
    return-object p0

    .line 273
    :cond_f
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->HealthScan:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 274
    .line 275
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 280
    .line 281
    .line 282
    move-result v0

    .line 283
    if-eqz v0, :cond_10

    .line 284
    .line 285
    sget-object p0, Lly/b;->u1:Lly/b;

    .line 286
    .line 287
    return-object p0

    .line 288
    :cond_10
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LauraQna:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 289
    .line 290
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 291
    .line 292
    .line 293
    move-result-object v0

    .line 294
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 295
    .line 296
    .line 297
    move-result v0

    .line 298
    if-eqz v0, :cond_11

    .line 299
    .line 300
    sget-object p0, Lly/b;->v1:Lly/b;

    .line 301
    .line 302
    return-object p0

    .line 303
    :cond_11
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LauraQnaInfo:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 304
    .line 305
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 310
    .line 311
    .line 312
    move-result v0

    .line 313
    if-eqz v0, :cond_12

    .line 314
    .line 315
    sget-object p0, Lly/b;->w1:Lly/b;

    .line 316
    .line 317
    return-object p0

    .line 318
    :cond_12
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Inspect:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 319
    .line 320
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 325
    .line 326
    .line 327
    move-result v0

    .line 328
    if-eqz v0, :cond_13

    .line 329
    .line 330
    sget-object p0, Lly/b;->f:Lly/b;

    .line 331
    .line 332
    return-object p0

    .line 333
    :cond_13
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LegalDocuments:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 334
    .line 335
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 336
    .line 337
    .line 338
    move-result-object v0

    .line 339
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 340
    .line 341
    .line 342
    move-result v0

    .line 343
    if-eqz v0, :cond_14

    .line 344
    .line 345
    sget-object p0, Lly/b;->F1:Lly/b;

    .line 346
    .line 347
    return-object p0

    .line 348
    :cond_14
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LocationAccess:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 349
    .line 350
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 355
    .line 356
    .line 357
    move-result v0

    .line 358
    if-eqz v0, :cond_15

    .line 359
    .line 360
    sget-object p0, Lly/b;->A1:Lly/b;

    .line 361
    .line 362
    return-object p0

    .line 363
    :cond_15
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgram:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 364
    .line 365
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 370
    .line 371
    .line 372
    move-result v0

    .line 373
    if-eqz v0, :cond_16

    .line 374
    .line 375
    sget-object p0, Lly/b;->Y3:Lly/b;

    .line 376
    .line 377
    return-object p0

    .line 378
    :cond_16
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramIntro:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 379
    .line 380
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object v0

    .line 384
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 385
    .line 386
    .line 387
    move-result v0

    .line 388
    if-eqz v0, :cond_17

    .line 389
    .line 390
    sget-object p0, Lly/b;->Z3:Lly/b;

    .line 391
    .line 392
    return-object p0

    .line 393
    :cond_17
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramBadgeDetail:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 394
    .line 395
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 400
    .line 401
    .line 402
    move-result v0

    .line 403
    if-eqz v0, :cond_18

    .line 404
    .line 405
    sget-object p0, Lly/b;->r4:Lly/b;

    .line 406
    .line 407
    return-object p0

    .line 408
    :cond_18
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramChallengeFailed:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 409
    .line 410
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 415
    .line 416
    .line 417
    move-result v0

    .line 418
    if-eqz v0, :cond_19

    .line 419
    .line 420
    sget-object p0, Lly/b;->n4:Lly/b;

    .line 421
    .line 422
    return-object p0

    .line 423
    :cond_19
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramChallengeCompleted:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 424
    .line 425
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 426
    .line 427
    .line 428
    move-result-object v0

    .line 429
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 430
    .line 431
    .line 432
    move-result v0

    .line 433
    if-eqz v0, :cond_1a

    .line 434
    .line 435
    sget-object p0, Lly/b;->l4:Lly/b;

    .line 436
    .line 437
    return-object p0

    .line 438
    :cond_1a
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramCollectedBadge:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 439
    .line 440
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 445
    .line 446
    .line 447
    move-result v0

    .line 448
    if-eqz v0, :cond_1b

    .line 449
    .line 450
    sget-object p0, Lly/b;->j4:Lly/b;

    .line 451
    .line 452
    return-object p0

    .line 453
    :cond_1b
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Maps:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 454
    .line 455
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 456
    .line 457
    .line 458
    move-result-object v0

    .line 459
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 460
    .line 461
    .line 462
    move-result v0

    .line 463
    if-eqz v0, :cond_1c

    .line 464
    .line 465
    sget-object p0, Lly/b;->e:Lly/b;

    .line 466
    .line 467
    return-object p0

    .line 468
    :cond_1c
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->MessageCenter:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 469
    .line 470
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 475
    .line 476
    .line 477
    move-result v0

    .line 478
    if-eqz v0, :cond_1d

    .line 479
    .line 480
    sget-object p0, Lly/b;->j2:Lly/b;

    .line 481
    .line 482
    return-object p0

    .line 483
    :cond_1d
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->NotificationSettings:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 484
    .line 485
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 486
    .line 487
    .line 488
    move-result-object v0

    .line 489
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 490
    .line 491
    .line 492
    move-result v0

    .line 493
    if-eqz v0, :cond_1e

    .line 494
    .line 495
    sget-object p0, Lly/b;->l2:Lly/b;

    .line 496
    .line 497
    return-object p0

    .line 498
    :cond_1e
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->OnlineRemoteUpdate:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 499
    .line 500
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 501
    .line 502
    .line 503
    move-result-object v0

    .line 504
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 505
    .line 506
    .line 507
    move-result v0

    .line 508
    if-eqz v0, :cond_1f

    .line 509
    .line 510
    sget-object p0, Lly/b;->S4:Lly/b;

    .line 511
    .line 512
    return-object p0

    .line 513
    :cond_1f
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->PayToFuelDisclaimer:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 514
    .line 515
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object v0

    .line 519
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 520
    .line 521
    .line 522
    move-result v0

    .line 523
    if-eqz v0, :cond_20

    .line 524
    .line 525
    sget-object p0, Lly/b;->L2:Lly/b;

    .line 526
    .line 527
    return-object p0

    .line 528
    :cond_20
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->PayToFuelSummary:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 529
    .line 530
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 531
    .line 532
    .line 533
    move-result-object v0

    .line 534
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 535
    .line 536
    .line 537
    move-result v0

    .line 538
    if-eqz v0, :cond_21

    .line 539
    .line 540
    sget-object p0, Lly/b;->M2:Lly/b;

    .line 541
    .line 542
    return-object p0

    .line 543
    :cond_21
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->PayToFuelSummaryError:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 544
    .line 545
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 546
    .line 547
    .line 548
    move-result-object v0

    .line 549
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 550
    .line 551
    .line 552
    move-result v0

    .line 553
    if-eqz v0, :cond_22

    .line 554
    .line 555
    sget-object p0, Lly/b;->N2:Lly/b;

    .line 556
    .line 557
    return-object p0

    .line 558
    :cond_22
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Powerpass:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 559
    .line 560
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 565
    .line 566
    .line 567
    move-result v0

    .line 568
    if-eqz v0, :cond_23

    .line 569
    .line 570
    sget-object p0, Lly/b;->x:Lly/b;

    .line 571
    .line 572
    return-object p0

    .line 573
    :cond_23
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ServicePartner:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 574
    .line 575
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 576
    .line 577
    .line 578
    move-result-object v0

    .line 579
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 580
    .line 581
    .line 582
    move-result v0

    .line 583
    if-eqz v0, :cond_24

    .line 584
    .line 585
    sget-object p0, Lly/b;->e3:Lly/b;

    .line 586
    .line 587
    return-object p0

    .line 588
    :cond_24
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Settings:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 589
    .line 590
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 591
    .line 592
    .line 593
    move-result-object v0

    .line 594
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 595
    .line 596
    .line 597
    move-result v0

    .line 598
    if-eqz v0, :cond_25

    .line 599
    .line 600
    sget-object p0, Lly/b;->i:Lly/b;

    .line 601
    .line 602
    return-object p0

    .line 603
    :cond_25
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ThirdPartyOffers:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 604
    .line 605
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 606
    .line 607
    .line 608
    move-result-object v0

    .line 609
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 610
    .line 611
    .line 612
    move-result v0

    .line 613
    if-eqz v0, :cond_26

    .line 614
    .line 615
    sget-object p0, Lly/b;->E1:Lly/b;

    .line 616
    .line 617
    return-object p0

    .line 618
    :cond_26
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Subscriptions:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 619
    .line 620
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 621
    .line 622
    .line 623
    move-result-object v0

    .line 624
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 625
    .line 626
    .line 627
    move-result v0

    .line 628
    if-eqz v0, :cond_27

    .line 629
    .line 630
    sget-object p0, Lly/b;->q3:Lly/b;

    .line 631
    .line 632
    return-object p0

    .line 633
    :cond_27
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->VehicleServicesBackup:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 634
    .line 635
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 636
    .line 637
    .line 638
    move-result-object v0

    .line 639
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 640
    .line 641
    .line 642
    move-result v0

    .line 643
    if-eqz v0, :cond_28

    .line 644
    .line 645
    sget-object p0, Lly/b;->C3:Lly/b;

    .line 646
    .line 647
    return-object p0

    .line 648
    :cond_28
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->VehicleDetailsHowToVideos:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 649
    .line 650
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 651
    .line 652
    .line 653
    move-result-object v0

    .line 654
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 655
    .line 656
    .line 657
    move-result v0

    .line 658
    if-eqz v0, :cond_29

    .line 659
    .line 660
    sget-object p0, Lly/b;->L3:Lly/b;

    .line 661
    .line 662
    return-object p0

    .line 663
    :cond_29
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->VehicleStatus:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 664
    .line 665
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 666
    .line 667
    .line 668
    move-result-object v0

    .line 669
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 670
    .line 671
    .line 672
    move-result v0

    .line 673
    if-eqz v0, :cond_2a

    .line 674
    .line 675
    sget-object p0, Lly/b;->G3:Lly/b;

    .line 676
    .line 677
    return-object p0

    .line 678
    :cond_2a
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->QrScan:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 679
    .line 680
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 681
    .line 682
    .line 683
    move-result-object v0

    .line 684
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 685
    .line 686
    .line 687
    move-result v0

    .line 688
    if-eqz v0, :cond_2b

    .line 689
    .line 690
    sget-object p0, Lly/b;->e0:Lly/b;

    .line 691
    .line 692
    return-object p0

    .line 693
    :cond_2b
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Logout:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 694
    .line 695
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 696
    .line 697
    .line 698
    move-result-object v0

    .line 699
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 700
    .line 701
    .line 702
    move-result v0

    .line 703
    if-nez v0, :cond_2e

    .line 704
    .line 705
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ChangeEnvironment:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 706
    .line 707
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 708
    .line 709
    .line 710
    move-result-object v0

    .line 711
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 712
    .line 713
    .line 714
    move-result v0

    .line 715
    if-eqz v0, :cond_2c

    .line 716
    .line 717
    goto :goto_0

    .line 718
    :cond_2c
    sget-object v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Debugger:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 719
    .line 720
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 721
    .line 722
    .line 723
    move-result-object v0

    .line 724
    invoke-static {p0, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 725
    .line 726
    .line 727
    move-result p0

    .line 728
    if-eqz p0, :cond_2d

    .line 729
    .line 730
    sget-object p0, Lly/b;->R:Lly/b;

    .line 731
    .line 732
    return-object p0

    .line 733
    :cond_2d
    const/4 p0, 0x0

    .line 734
    return-object p0

    .line 735
    :cond_2e
    :goto_0
    sget-object p0, Lly/b;->M1:Lly/b;

    .line 736
    .line 737
    return-object p0

    .line 738
    :cond_2f
    :goto_1
    sget-object p0, Lly/b;->d:Lly/b;

    .line 739
    .line 740
    return-object p0
.end method

.method public static e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Parcelable;
    .locals 2

    .line 1
    const-class v0, Lrp/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "map_state"

    .line 14
    .line 15
    invoke-virtual {p1, v1}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    return-object p0

    .line 23
    :cond_0
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, p0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public static f(Landroid/os/Bundle;Landroid/os/Bundle;)V
    .locals 2

    .line 1
    const-string v0, "MapOptions"

    .line 2
    .line 3
    invoke-static {v0, p0}, Lrp/d;->e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Parcelable;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-static {p1, v0, v1}, Lrp/d;->g(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    const-string v0, "StreetViewPanoramaOptions"

    .line 13
    .line 14
    invoke-static {v0, p0}, Lrp/d;->e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Parcelable;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    invoke-static {p1, v0, v1}, Lrp/d;->g(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    const-string v0, "camera"

    .line 24
    .line 25
    invoke-static {v0, p0}, Lrp/d;->e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Parcelable;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    invoke-static {p1, v0, v1}, Lrp/d;->g(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 32
    .line 33
    .line 34
    :cond_2
    const-string v0, "position"

    .line 35
    .line 36
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_3

    .line 41
    .line 42
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    :cond_3
    const-string v0, "com.google.android.wearable.compat.extra.LOWBIT_AMBIENT"

    .line 50
    .line 51
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_4

    .line 56
    .line 57
    const/4 v1, 0x0

    .line 58
    invoke-virtual {p0, v0, v1}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    invoke-virtual {p1, v0, p0}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 63
    .line 64
    .line 65
    :cond_4
    return-void
.end method

.method public static g(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Parcelable;)V
    .locals 3

    .line 1
    const-class v0, Lrp/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "map_state"

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    new-instance v2, Landroid/os/Bundle;

    .line 22
    .line 23
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 24
    .line 25
    .line 26
    :cond_0
    invoke-virtual {v2, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v2, p1, p2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v1, v2}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method
