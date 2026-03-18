.class public final synthetic Lf2/h0;
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
    iput p1, p0, Lf2/h0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/work/impl/WorkDatabase_Impl;)V
    .locals 0

    .line 2
    const/4 p1, 0x6

    iput p1, p0, Lf2/h0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lf2/h0;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/time/format/DateTimeFormatterBuilder;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->parseCaseInsensitive()Ljava/time/format/DateTimeFormatterBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "+HHmmss"

    .line 16
    .line 17
    const-string v1, "Z"

    .line 18
    .line 19
    invoke-virtual {p0, v0, v1}, Ljava/time/format/DateTimeFormatterBuilder;->appendOffset(Ljava/lang/String;Ljava/lang/String;)Ljava/time/format/DateTimeFormatterBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter()Ljava/time/format/DateTimeFormatter;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_0
    new-instance p0, Ljava/time/format/DateTimeFormatterBuilder;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->parseCaseInsensitive()Ljava/time/format/DateTimeFormatterBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->appendOffsetId()Ljava/time/format/DateTimeFormatterBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter()Ljava/time/format/DateTimeFormatter;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :pswitch_1
    invoke-static {}, Lcz/myskoda/api/idk/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_2
    invoke-static {}, Lcz/myskoda/api/idk/infrastructure/ApiClient;->b()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_3
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_4
    new-instance p0, Lcom/squareup/moshi/Moshi$Builder;

    .line 60
    .line 61
    invoke-direct {p0}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 62
    .line 63
    .line 64
    sget-object v0, Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;->a:Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    sget-object v0, Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;->a:Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    new-instance v0, Lbx/d;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lcom/squareup/moshi/Moshi$Builder;->a:Ljava/util/ArrayList;

    .line 80
    .line 81
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    new-instance v0, Lcom/squareup/moshi/Moshi;

    .line 85
    .line 86
    invoke-direct {v0, p0}, Lcom/squareup/moshi/Moshi;-><init>(Lcom/squareup/moshi/Moshi$Builder;)V

    .line 87
    .line 88
    .line 89
    return-object v0

    .line 90
    :pswitch_5
    new-instance p0, Llj0/a;

    .line 91
    .line 92
    const-string v0, "vehicle_status_lock_unlocked"

    .line 93
    .line 94
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_6
    new-instance p0, Llj0/a;

    .line 99
    .line 100
    const-string v0, "vehicle_status_lock_locked"

    .line 101
    .line 102
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_7
    sget-object p0, Lfa0/a;->a:Lfa0/a;

    .line 107
    .line 108
    return-object p0

    .line 109
    :pswitch_8
    new-instance p0, Lkj0/h;

    .line 110
    .line 111
    const-string v0, "Units"

    .line 112
    .line 113
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_9
    new-instance p0, Lkj0/h;

    .line 118
    .line 119
    const-string v0, "Appearance"

    .line 120
    .line 121
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_a
    const-string p0, "createOutline() could not be created because of missing RPATheme.concreteSpacings!"

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_b
    const-string p0, "createOutline() could not be created because of missing RPATheme.concreteDimensions!"

    .line 129
    .line 130
    return-object p0

    .line 131
    :pswitch_c
    const-string p0, "(As requested) skipping compatibility check and assuming device is compatible."

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_d
    sget p0, Lg1/w0;->a:F

    .line 135
    .line 136
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_e
    sget-object p0, Lgz/h;->c:Lgz/h;

    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_f
    sget-object p0, Lgz/d;->c:Lgz/d;

    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_10
    sget-object p0, Lgz/b;->c:Lgz/b;

    .line 146
    .line 147
    return-object p0

    .line 148
    :pswitch_11
    invoke-static {}, Lcz/myskoda/api/bff_widgets/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    return-object p0

    .line 153
    :pswitch_12
    invoke-static {}, Lcz/myskoda/api/bff_widgets/v2/infrastructure/ApiClient;->a()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    return-object p0

    .line 158
    :pswitch_13
    const-string p0, "io.ktor.client.plugins.SaveBody"

    .line 159
    .line 160
    invoke-static {p0}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    return-object p0

    .line 165
    :pswitch_14
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 166
    .line 167
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    return-object p0

    .line 172
    :pswitch_15
    const/4 p0, 0x0

    .line 173
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :pswitch_16
    new-instance p0, Lmb/e;

    .line 179
    .line 180
    const/4 v0, 0x0

    .line 181
    invoke-direct {p0, v0}, Lmb/e;-><init>(I)V

    .line 182
    .line 183
    .line 184
    return-object p0

    .line 185
    :pswitch_17
    const-string p0, "Failed to parse BFFError from response body"

    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_18
    const-string p0, "Response is not saved, can not verify if BFFError present"

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_19
    new-instance p0, Lf2/w0;

    .line 192
    .line 193
    invoke-direct {p0}, Lf2/w0;-><init>()V

    .line 194
    .line 195
    .line 196
    return-object p0

    .line 197
    :pswitch_1a
    sget-object p0, Lf2/x0;->a:Lg4/p0;

    .line 198
    .line 199
    return-object p0

    .line 200
    :pswitch_1b
    new-instance p0, Lf2/k0;

    .line 201
    .line 202
    invoke-direct {p0}, Lf2/k0;-><init>()V

    .line 203
    .line 204
    .line 205
    return-object p0

    .line 206
    :pswitch_1c
    new-instance p0, Lf2/g0;

    .line 207
    .line 208
    invoke-direct {p0}, Lf2/g0;-><init>()V

    .line 209
    .line 210
    .line 211
    return-object p0

    .line 212
    nop

    .line 213
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
