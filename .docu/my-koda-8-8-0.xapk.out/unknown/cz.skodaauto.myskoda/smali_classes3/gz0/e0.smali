.class public final synthetic Lgz0/e0;
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
    iput p1, p0, Lgz0/e0;->d:I

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
    .locals 5

    .line 1
    iget p0, p0, Lgz0/e0;->d:I

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const-string v3, "system://share"

    .line 7
    .line 8
    const-string v4, "badge_share_button"

    .line 9
    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, Llj0/a;

    .line 14
    .line 15
    const-string v0, "edit_route"

    .line 16
    .line 17
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_0
    new-instance p0, Llj0/a;

    .line 22
    .line 23
    const-string v0, "discard_route"

    .line 24
    .line 25
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_1
    new-instance p0, Llj0/a;

    .line 30
    .line 31
    const-string v0, "maps_route_button_set_level"

    .line 32
    .line 33
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_2
    new-instance p0, Llj0/a;

    .line 38
    .line 39
    const-string v0, "route_adjustment_cancelled"

    .line 40
    .line 41
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_3
    new-instance p0, Llj0/a;

    .line 46
    .line 47
    const-string v0, "delete_route"

    .line 48
    .line 49
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_4
    new-instance p0, Llj0/b;

    .line 54
    .line 55
    invoke-direct {p0, v4, v3}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_5
    new-instance p0, Llj0/b;

    .line 60
    .line 61
    invoke-direct {p0, v4, v3}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_6
    new-instance p0, Lh2/dc;

    .line 66
    .line 67
    invoke-direct {p0}, Lh2/dc;-><init>()V

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_7
    sget-object p0, Lk2/r0;->a:Lg4/p0;

    .line 72
    .line 73
    return-object p0

    .line 74
    :pswitch_8
    const/4 p0, 0x0

    .line 75
    int-to-float p0, p0

    .line 76
    new-instance v0, Lt4/f;

    .line 77
    .line 78
    invoke-direct {v0, p0}, Lt4/f;-><init>(F)V

    .line 79
    .line 80
    .line 81
    return-object v0

    .line 82
    :pswitch_9
    new-instance p0, Lh2/h8;

    .line 83
    .line 84
    invoke-direct {p0}, Lh2/h8;-><init>()V

    .line 85
    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_a
    new-instance p0, Lh2/v7;

    .line 89
    .line 90
    sget-wide v0, Le3/s;->i:J

    .line 91
    .line 92
    invoke-direct {p0, v0, v1, v2}, Lh2/v7;-><init>(JLg2/b;)V

    .line 93
    .line 94
    .line 95
    return-object p0

    .line 96
    :pswitch_b
    sget p0, Lh2/q6;->a:F

    .line 97
    .line 98
    sget-object p0, Lh2/i4;->a:Lh2/i4;

    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_c
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    :pswitch_d
    sget-object p0, Lh2/m6;->a:Lh2/m6;

    .line 107
    .line 108
    return-object p0

    .line 109
    :pswitch_e
    sget-object p0, Lh2/l5;->a:Ll2/u2;

    .line 110
    .line 111
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 112
    .line 113
    return-object p0

    .line 114
    :pswitch_f
    const/16 p0, 0x30

    .line 115
    .line 116
    int-to-float p0, p0

    .line 117
    new-instance v0, Lt4/f;

    .line 118
    .line 119
    invoke-direct {v0, p0}, Lt4/f;-><init>(F)V

    .line 120
    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_10
    sget-object p0, Lh2/k5;->a:Lt3/o;

    .line 124
    .line 125
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_11
    const/high16 p0, 0x3f800000    # 1.0f

    .line 129
    .line 130
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :pswitch_12
    const/4 p0, 0x0

    .line 136
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0

    .line 141
    :pswitch_13
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 142
    .line 143
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_14
    new-instance p0, Ll4/v;

    .line 149
    .line 150
    const/4 v3, 0x7

    .line 151
    invoke-direct {p0, v0, v1, v2, v3}, Ll4/v;-><init>(JLjava/lang/String;I)V

    .line 152
    .line 153
    .line 154
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0

    .line 159
    :pswitch_15
    sget-object p0, Lh2/g1;->a:Ll2/u2;

    .line 160
    .line 161
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_16
    const/4 p0, -0x1

    .line 165
    invoke-static {p0, v0, v1, v0, v1}, Lh2/g1;->e(IJJ)Lh2/f1;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    return-object p0

    .line 170
    :pswitch_17
    sget-object p0, Lh2/q;->a:Ll2/e0;

    .line 171
    .line 172
    sget-object p0, Lh2/v3;->b:Lh2/v3;

    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_18
    sget-object p0, Lh2/q;->a:Ll2/e0;

    .line 176
    .line 177
    sget-object p0, Lh2/m4;->a:Lh2/m4;

    .line 178
    .line 179
    return-object p0

    .line 180
    :pswitch_19
    sget p0, Lh2/j;->a:F

    .line 181
    .line 182
    sget-object p0, Lh2/h4;->a:Lh2/h4;

    .line 183
    .line 184
    return-object p0

    .line 185
    :pswitch_1a
    const-string p0, "Unable to finish vehicle activation. Vin is null."

    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_1b
    new-instance p0, Ljava/time/format/DateTimeFormatterBuilder;

    .line 189
    .line 190
    invoke-direct {p0}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 191
    .line 192
    .line 193
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->parseCaseInsensitive()Ljava/time/format/DateTimeFormatterBuilder;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    sget-object v0, Ljava/time/temporal/ChronoField;->YEAR:Ljava/time/temporal/ChronoField;

    .line 198
    .line 199
    const/16 v1, 0xa

    .line 200
    .line 201
    sget-object v2, Ljava/time/format/SignStyle;->EXCEEDS_PAD:Ljava/time/format/SignStyle;

    .line 202
    .line 203
    const/4 v3, 0x4

    .line 204
    invoke-virtual {p0, v0, v3, v1, v2}, Ljava/time/format/DateTimeFormatterBuilder;->appendValue(Ljava/time/temporal/TemporalField;IILjava/time/format/SignStyle;)Ljava/time/format/DateTimeFormatterBuilder;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    const/16 v0, 0x2d

    .line 209
    .line 210
    invoke-virtual {p0, v0}, Ljava/time/format/DateTimeFormatterBuilder;->appendLiteral(C)Ljava/time/format/DateTimeFormatterBuilder;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    sget-object v0, Ljava/time/temporal/ChronoField;->MONTH_OF_YEAR:Ljava/time/temporal/ChronoField;

    .line 215
    .line 216
    const/4 v1, 0x2

    .line 217
    invoke-virtual {p0, v0, v1}, Ljava/time/format/DateTimeFormatterBuilder;->appendValue(Ljava/time/temporal/TemporalField;I)Ljava/time/format/DateTimeFormatterBuilder;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter()Ljava/time/format/DateTimeFormatter;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    return-object p0

    .line 226
    :pswitch_1c
    new-instance p0, Ljava/time/format/DateTimeFormatterBuilder;

    .line 227
    .line 228
    invoke-direct {p0}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 229
    .line 230
    .line 231
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->parseCaseInsensitive()Ljava/time/format/DateTimeFormatterBuilder;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    const-string v0, "+HHMM"

    .line 236
    .line 237
    const-string v1, "+0000"

    .line 238
    .line 239
    invoke-virtual {p0, v0, v1}, Ljava/time/format/DateTimeFormatterBuilder;->appendOffset(Ljava/lang/String;Ljava/lang/String;)Ljava/time/format/DateTimeFormatterBuilder;

    .line 240
    .line 241
    .line 242
    move-result-object p0

    .line 243
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter()Ljava/time/format/DateTimeFormatter;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    return-object p0

    .line 248
    nop

    .line 249
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
