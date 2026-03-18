.class public final Lur0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Lod0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lur0/h;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Lod0/h;

    .line 7
    .line 8
    const/16 v0, 0x9

    .line 9
    .line 10
    invoke-direct {p1, p0, v0}, Lod0/h;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lur0/h;->b:Lod0/h;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Ljava/lang/String;)Lyr0/c;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto/16 :goto_0

    .line 9
    .line 10
    :sswitch_0
    const-string v0, "Product"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    sget-object p0, Lyr0/c;->s:Lyr0/c;

    .line 19
    .line 20
    return-object p0

    .line 21
    :sswitch_1
    const-string v0, "SocialNetwork"

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    sget-object p0, Lyr0/c;->w:Lyr0/c;

    .line 30
    .line 31
    return-object p0

    .line 32
    :sswitch_2
    const-string v0, "ThirdPartyBlock"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    sget-object p0, Lyr0/c;->y:Lyr0/c;

    .line 41
    .line 42
    return-object p0

    .line 43
    :sswitch_3
    const-string v0, "LoyaltyProgram"

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_0

    .line 50
    .line 51
    sget-object p0, Lyr0/c;->o:Lyr0/c;

    .line 52
    .line 53
    return-object p0

    .line 54
    :sswitch_4
    const-string v0, "Phone"

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_0

    .line 61
    .line 62
    sget-object p0, Lyr0/c;->r:Lyr0/c;

    .line 63
    .line 64
    return-object p0

    .line 65
    :sswitch_5
    const-string v0, "Email"

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_0

    .line 72
    .line 73
    sget-object p0, Lyr0/c;->j:Lyr0/c;

    .line 74
    .line 75
    return-object p0

    .line 76
    :sswitch_6
    const-string v0, "Chat"

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_0

    .line 83
    .line 84
    sget-object p0, Lyr0/c;->g:Lyr0/c;

    .line 85
    .line 86
    return-object p0

    .line 87
    :sswitch_7
    const-string v0, "Sms"

    .line 88
    .line 89
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_0

    .line 94
    .line 95
    sget-object p0, Lyr0/c;->v:Lyr0/c;

    .line 96
    .line 97
    return-object p0

    .line 98
    :sswitch_8
    const-string v0, "Fax"

    .line 99
    .line 100
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-eqz v0, :cond_0

    .line 105
    .line 106
    sget-object p0, Lyr0/c;->l:Lyr0/c;

    .line 107
    .line 108
    return-object p0

    .line 109
    :sswitch_9
    const-string v0, "Magazine"

    .line 110
    .line 111
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-eqz v0, :cond_0

    .line 116
    .line 117
    sget-object p0, Lyr0/c;->p:Lyr0/c;

    .line 118
    .line 119
    return-object p0

    .line 120
    :sswitch_a
    const-string v0, "EventInvitation"

    .line 121
    .line 122
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-eqz v0, :cond_0

    .line 127
    .line 128
    sget-object p0, Lyr0/c;->k:Lyr0/c;

    .line 129
    .line 130
    return-object p0

    .line 131
    :sswitch_b
    const-string v0, "Robinson"

    .line 132
    .line 133
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    if-eqz v0, :cond_0

    .line 138
    .line 139
    sget-object p0, Lyr0/c;->u:Lyr0/c;

    .line 140
    .line 141
    return-object p0

    .line 142
    :sswitch_c
    const-string v0, "BrandDealerBlock"

    .line 143
    .line 144
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    if-eqz v0, :cond_0

    .line 149
    .line 150
    sget-object p0, Lyr0/c;->f:Lyr0/c;

    .line 151
    .line 152
    return-object p0

    .line 153
    :sswitch_d
    const-string v0, "GeneralBrandBlock"

    .line 154
    .line 155
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    if-eqz v0, :cond_0

    .line 160
    .line 161
    sget-object p0, Lyr0/c;->m:Lyr0/c;

    .line 162
    .line 163
    return-object p0

    .line 164
    :sswitch_e
    const-string v0, "CssBlock"

    .line 165
    .line 166
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    if-eqz v0, :cond_0

    .line 171
    .line 172
    sget-object p0, Lyr0/c;->i:Lyr0/c;

    .line 173
    .line 174
    return-object p0

    .line 175
    :sswitch_f
    const-string v0, "Commercial"

    .line 176
    .line 177
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    if-eqz v0, :cond_0

    .line 182
    .line 183
    sget-object p0, Lyr0/c;->h:Lyr0/c;

    .line 184
    .line 185
    return-object p0

    .line 186
    :sswitch_10
    const-string v0, "Survey"

    .line 187
    .line 188
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v0

    .line 192
    if-eqz v0, :cond_0

    .line 193
    .line 194
    sget-object p0, Lyr0/c;->x:Lyr0/c;

    .line 195
    .line 196
    return-object p0

    .line 197
    :sswitch_11
    const-string v0, "Mobile"

    .line 198
    .line 199
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v0

    .line 203
    if-eqz v0, :cond_0

    .line 204
    .line 205
    sget-object p0, Lyr0/c;->q:Lyr0/c;

    .line 206
    .line 207
    return-object p0

    .line 208
    :sswitch_12
    const-string v0, "RequestedByCustomer"

    .line 209
    .line 210
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v0

    .line 214
    if-eqz v0, :cond_0

    .line 215
    .line 216
    sget-object p0, Lyr0/c;->t:Lyr0/c;

    .line 217
    .line 218
    return-object p0

    .line 219
    :sswitch_13
    const-string v0, "Letter"

    .line 220
    .line 221
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v0

    .line 225
    if-eqz v0, :cond_0

    .line 226
    .line 227
    sget-object p0, Lyr0/c;->n:Lyr0/c;

    .line 228
    .line 229
    return-object p0

    .line 230
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 231
    .line 232
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 233
    .line 234
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    throw v0

    .line 242
    nop

    .line 243
    :sswitch_data_0
    .sparse-switch
        -0x7889efba -> :sswitch_13
        -0x77f80cbd -> :sswitch_12
        -0x7650833e -> :sswitch_11
        -0x6bb76c86 -> :sswitch_10
        -0x53656896 -> :sswitch_f
        -0x44927f96 -> :sswitch_e
        -0x314937d2 -> :sswitch_d
        -0x2e1bebf3 -> :sswitch_c
        -0x1cd5a038 -> :sswitch_b
        -0xde87a4d -> :sswitch_a
        -0xb5f04c -> :sswitch_9
        0x112fd -> :sswitch_8
        0x14539 -> :sswitch_7
        0x200778 -> :sswitch_6
        0x3ff5b7c -> :sswitch_5
        0x4984d4e -> :sswitch_4
        0x2e7a837e -> :sswitch_3
        0x3a115dee -> :sswitch_2
        0x431945e1 -> :sswitch_1
        0x50c664cf -> :sswitch_0
    .end sparse-switch
.end method
