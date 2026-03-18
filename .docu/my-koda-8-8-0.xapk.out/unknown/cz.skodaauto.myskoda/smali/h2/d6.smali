.class public final synthetic Lh2/d6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLl2/t2;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lh2/d6;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lh2/d6;->e:J

    iput-object p3, p0, Lh2/d6;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;JI)V
    .locals 0

    .line 2
    iput p4, p0, Lh2/d6;->d:I

    iput-object p1, p0, Lh2/d6;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lh2/d6;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/d6;->d:I

    .line 4
    .line 5
    const-string v2, "url"

    .line 6
    .line 7
    iget-wide v3, v0, Lh2/d6;->e:J

    .line 8
    .line 9
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    iget-object v6, v0, Lh2/d6;->f:Ljava/lang/Object;

    .line 12
    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    check-cast v6, Lzb/v0;

    .line 17
    .line 18
    move-object/from16 v0, p1

    .line 19
    .line 20
    check-cast v0, Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    new-instance v1, Lmb/p;

    .line 26
    .line 27
    invoke-direct {v1, v3, v4, v0}, Lmb/p;-><init>(JLjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v6, v1}, Lzb/v0;->g(Lay0/k;)V

    .line 31
    .line 32
    .line 33
    return-object v5

    .line 34
    :pswitch_0
    check-cast v6, Landroid/content/Context;

    .line 35
    .line 36
    move-object/from16 v0, p1

    .line 37
    .line 38
    check-cast v0, Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v3, v4}, Le3/j0;->z(J)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    const/high16 v2, -0x1000000

    .line 48
    .line 49
    or-int/2addr v1, v2

    .line 50
    new-instance v2, Lvv0/d;

    .line 51
    .line 52
    invoke-direct {v2}, Lvv0/d;-><init>()V

    .line 53
    .line 54
    .line 55
    new-instance v3, Landroid/os/Bundle;

    .line 56
    .line 57
    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V

    .line 58
    .line 59
    .line 60
    const-string v4, "android.support.customtabs.extra.TOOLBAR_COLOR"

    .line 61
    .line 62
    invoke-virtual {v3, v4, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 63
    .line 64
    .line 65
    iput-object v3, v2, Lvv0/d;->e:Ljava/lang/Object;

    .line 66
    .line 67
    iget-object v1, v2, Lvv0/d;->b:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v1, Landroid/content/Intent;

    .line 70
    .line 71
    const-string v3, "android.support.customtabs.extra.TITLE_VISIBILITY"

    .line 72
    .line 73
    const/4 v4, 0x1

    .line 74
    invoke-virtual {v1, v3, v4}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2}, Lvv0/d;->c()Lc2/k;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iget-object v2, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v2, Landroid/content/Intent;

    .line 88
    .line 89
    invoke-virtual {v2, v0}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 90
    .line 91
    .line 92
    iget-object v0, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v0, Landroid/os/Bundle;

    .line 95
    .line 96
    invoke-virtual {v6, v2, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V

    .line 97
    .line 98
    .line 99
    return-object v5

    .line 100
    :pswitch_1
    check-cast v6, Lt1/p0;

    .line 101
    .line 102
    move-object/from16 v7, p1

    .line 103
    .line 104
    check-cast v7, Lg3/d;

    .line 105
    .line 106
    iget-object v1, v6, Lt1/p0;->s:Ll2/j1;

    .line 107
    .line 108
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    check-cast v1, Ljava/lang/Boolean;

    .line 113
    .line 114
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result v1

    .line 118
    if-nez v1, :cond_0

    .line 119
    .line 120
    iget-object v1, v6, Lt1/p0;->t:Ll2/j1;

    .line 121
    .line 122
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    check-cast v1, Ljava/lang/Boolean;

    .line 127
    .line 128
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    if-eqz v1, :cond_1

    .line 133
    .line 134
    :cond_0
    const/16 v16, 0x0

    .line 135
    .line 136
    const/16 v17, 0x7e

    .line 137
    .line 138
    iget-wide v8, v0, Lh2/d6;->e:J

    .line 139
    .line 140
    const-wide/16 v10, 0x0

    .line 141
    .line 142
    const-wide/16 v12, 0x0

    .line 143
    .line 144
    const/4 v14, 0x0

    .line 145
    const/4 v15, 0x0

    .line 146
    invoke-static/range {v7 .. v17}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 147
    .line 148
    .line 149
    :cond_1
    return-object v5

    .line 150
    :pswitch_2
    check-cast v6, Lo1/t;

    .line 151
    .line 152
    move-object/from16 v0, p1

    .line 153
    .line 154
    check-cast v0, Lc1/c;

    .line 155
    .line 156
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    check-cast v0, Lt4/j;

    .line 161
    .line 162
    iget-wide v0, v0, Lt4/j;->a:J

    .line 163
    .line 164
    invoke-static {v0, v1, v3, v4}, Lt4/j;->c(JJ)J

    .line 165
    .line 166
    .line 167
    move-result-wide v0

    .line 168
    sget v2, Lo1/t;->t:I

    .line 169
    .line 170
    invoke-virtual {v6, v0, v1}, Lo1/t;->g(J)V

    .line 171
    .line 172
    .line 173
    iget-object v0, v6, Lo1/t;->c:Lmc/e;

    .line 174
    .line 175
    invoke-virtual {v0}, Lmc/e;->invoke()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    return-object v5

    .line 179
    :pswitch_3
    check-cast v6, Ll2/t2;

    .line 180
    .line 181
    move-object/from16 v7, p1

    .line 182
    .line 183
    check-cast v7, Lg3/d;

    .line 184
    .line 185
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    check-cast v1, Ljava/lang/Number;

    .line 190
    .line 191
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    const/4 v2, 0x0

    .line 196
    const/high16 v3, 0x3f800000    # 1.0f

    .line 197
    .line 198
    invoke-static {v1, v2, v3}, Lkp/r9;->d(FFF)F

    .line 199
    .line 200
    .line 201
    move-result v14

    .line 202
    const/16 v16, 0x0

    .line 203
    .line 204
    const/16 v17, 0x76

    .line 205
    .line 206
    iget-wide v8, v0, Lh2/d6;->e:J

    .line 207
    .line 208
    const-wide/16 v10, 0x0

    .line 209
    .line 210
    const-wide/16 v12, 0x0

    .line 211
    .line 212
    const/4 v15, 0x0

    .line 213
    invoke-static/range {v7 .. v17}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 214
    .line 215
    .line 216
    return-object v5

    .line 217
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
