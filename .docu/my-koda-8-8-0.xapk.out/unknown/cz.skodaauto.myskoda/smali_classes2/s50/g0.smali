.class public final Ls50/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# static fields
.field public static final c:J

.field public static final d:J


# instance fields
.field public final a:Ls50/j;

.field public final b:Lmy0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    sget-object v0, Lmy0/e;->k:Lmy0/e;

    .line 4
    .line 5
    const/4 v1, 0x7

    .line 6
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 7
    .line 8
    .line 9
    move-result-wide v1

    .line 10
    sput-wide v1, Ls50/g0;->c:J

    .line 11
    .line 12
    const/16 v1, 0x1e

    .line 13
    .line 14
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    sput-wide v0, Ls50/g0;->d:J

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(Ls50/j;)V
    .locals 1

    .line 1
    sget-object v0, Lmy0/a;->e:Lmy0/a;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ls50/g0;->a:Ls50/j;

    .line 7
    .line 8
    iput-object v0, p0, Ls50/g0;->b:Lmy0/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Ls50/g0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Ls50/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ls50/e0;

    .line 7
    .line 8
    iget v1, v0, Ls50/e0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ls50/e0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ls50/e0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ls50/e0;-><init>(Ls50/g0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ls50/e0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ls50/e0;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Ls50/g0;->a:Ls50/j;

    .line 32
    .line 33
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    packed-switch v2, :pswitch_data_0

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object v4

    .line 50
    :pswitch_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object v4

    .line 54
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    return-object v4

    .line 58
    :pswitch_3
    iget-wide v5, v0, Ls50/e0;->d:J

    .line 59
    .line 60
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_3

    .line 64
    :pswitch_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_2

    .line 68
    :pswitch_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    const/4 p1, 0x1

    .line 76
    iput p1, v0, Ls50/e0;->g:I

    .line 77
    .line 78
    move-object p1, v3

    .line 79
    check-cast p1, Lp50/i;

    .line 80
    .line 81
    invoke-virtual {p1, v0}, Lp50/i;->b(Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    if-ne p1, v1, :cond_1

    .line 86
    .line 87
    goto/16 :goto_8

    .line 88
    .line 89
    :cond_1
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-eqz p1, :cond_2

    .line 96
    .line 97
    goto/16 :goto_9

    .line 98
    .line 99
    :cond_2
    const/4 p1, 0x2

    .line 100
    iput p1, v0, Ls50/e0;->g:I

    .line 101
    .line 102
    move-object p1, v3

    .line 103
    check-cast p1, Lp50/i;

    .line 104
    .line 105
    invoke-virtual {p1, v0}, Lp50/i;->a(Lrx0/c;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    if-ne p1, v1, :cond_3

    .line 110
    .line 111
    goto/16 :goto_8

    .line 112
    .line 113
    :cond_3
    :goto_2
    check-cast p1, Ljava/lang/Number;

    .line 114
    .line 115
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 116
    .line 117
    .line 118
    move-result-wide v5

    .line 119
    iput-wide v5, v0, Ls50/e0;->d:J

    .line 120
    .line 121
    const/4 p1, 0x3

    .line 122
    iput p1, v0, Ls50/e0;->g:I

    .line 123
    .line 124
    move-object p1, v3

    .line 125
    check-cast p1, Lp50/i;

    .line 126
    .line 127
    iget-object p1, p1, Lp50/i;->a:Lve0/u;

    .line 128
    .line 129
    const-string v2, "PREF_DIGITAL_CARD_WAS_DISMISSED"

    .line 130
    .line 131
    const/4 v7, 0x0

    .line 132
    invoke-virtual {p1, v7, v2, v0}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    if-ne p1, v1, :cond_4

    .line 137
    .line 138
    goto/16 :goto_8

    .line 139
    .line 140
    :cond_4
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 141
    .line 142
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    const-wide/16 v7, 0x0

    .line 147
    .line 148
    cmp-long v2, v5, v7

    .line 149
    .line 150
    const-string v5, "PREF_DIGITAL_CARD_NEXT_SHOW_DATE"

    .line 151
    .line 152
    if-nez v2, :cond_7

    .line 153
    .line 154
    if-nez p1, :cond_7

    .line 155
    .line 156
    const/4 p1, 0x4

    .line 157
    iput p1, v0, Ls50/e0;->g:I

    .line 158
    .line 159
    iget-object p0, p0, Ls50/g0;->b:Lmy0/b;

    .line 160
    .line 161
    invoke-interface {p0}, Lmy0/b;->now()Lmy0/f;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    invoke-virtual {p0}, Lmy0/f;->a()J

    .line 166
    .line 167
    .line 168
    move-result-wide p0

    .line 169
    sget-wide v6, Ls50/g0;->c:J

    .line 170
    .line 171
    invoke-static {v6, v7}, Lmy0/c;->e(J)J

    .line 172
    .line 173
    .line 174
    move-result-wide v6

    .line 175
    add-long/2addr v6, p0

    .line 176
    check-cast v3, Lp50/i;

    .line 177
    .line 178
    iget-object p0, v3, Lp50/i;->a:Lve0/u;

    .line 179
    .line 180
    invoke-virtual {p0, v5, v6, v7, v0}, Lve0/u;->m(Ljava/lang/String;JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    if-ne p0, v1, :cond_5

    .line 185
    .line 186
    goto :goto_4

    .line 187
    :cond_5
    move-object p0, v4

    .line 188
    :goto_4
    if-ne p0, v1, :cond_6

    .line 189
    .line 190
    goto :goto_5

    .line 191
    :cond_6
    move-object p0, v4

    .line 192
    :goto_5
    if-ne p0, v1, :cond_b

    .line 193
    .line 194
    goto :goto_8

    .line 195
    :cond_7
    if-eqz v2, :cond_8

    .line 196
    .line 197
    if-nez p1, :cond_8

    .line 198
    .line 199
    const/4 p1, 0x5

    .line 200
    iput p1, v0, Ls50/e0;->g:I

    .line 201
    .line 202
    invoke-virtual {p0, v0}, Ls50/g0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    if-ne p0, v1, :cond_b

    .line 207
    .line 208
    goto :goto_8

    .line 209
    :cond_8
    if-eqz v2, :cond_b

    .line 210
    .line 211
    if-eqz p1, :cond_b

    .line 212
    .line 213
    const/4 p0, 0x6

    .line 214
    iput p0, v0, Ls50/e0;->g:I

    .line 215
    .line 216
    check-cast v3, Lp50/i;

    .line 217
    .line 218
    iget-object p0, v3, Lp50/i;->a:Lve0/u;

    .line 219
    .line 220
    const-wide/16 v2, -0x1

    .line 221
    .line 222
    invoke-virtual {p0, v5, v2, v3, v0}, Lve0/u;->m(Ljava/lang/String;JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    if-ne p0, v1, :cond_9

    .line 227
    .line 228
    goto :goto_6

    .line 229
    :cond_9
    move-object p0, v4

    .line 230
    :goto_6
    if-ne p0, v1, :cond_a

    .line 231
    .line 232
    goto :goto_7

    .line 233
    :cond_a
    move-object p0, v4

    .line 234
    :goto_7
    if-ne p0, v1, :cond_b

    .line 235
    .line 236
    :goto_8
    return-object v1

    .line 237
    :cond_b
    :goto_9
    return-object v4

    .line 238
    nop

    .line 239
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Ls50/f0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ls50/f0;

    .line 7
    .line 8
    iget v1, v0, Ls50/f0;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ls50/f0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ls50/f0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ls50/f0;-><init>(Ls50/g0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ls50/f0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ls50/f0;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    iget-object v4, p0, Ls50/g0;->a:Ls50/j;

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v6, :cond_2

    .line 40
    .line 41
    if-ne v2, v5, :cond_1

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-object v3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v6, v0, Ls50/f0;->f:I

    .line 63
    .line 64
    move-object p1, v4

    .line 65
    check-cast p1, Lp50/i;

    .line 66
    .line 67
    iget-object p1, p1, Lp50/i;->a:Lve0/u;

    .line 68
    .line 69
    const-string v2, "PREF_DIGITAL_CARD_WAS_DISMISSED"

    .line 70
    .line 71
    invoke-virtual {p1, v6, v2, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_4

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_4
    move-object p1, v3

    .line 79
    :goto_1
    if-ne p1, v1, :cond_5

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_5
    :goto_2
    iget-object p0, p0, Ls50/g0;->b:Lmy0/b;

    .line 83
    .line 84
    invoke-interface {p0}, Lmy0/b;->now()Lmy0/f;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {p0}, Lmy0/f;->a()J

    .line 89
    .line 90
    .line 91
    move-result-wide p0

    .line 92
    sget-wide v6, Ls50/g0;->d:J

    .line 93
    .line 94
    invoke-static {v6, v7}, Lmy0/c;->e(J)J

    .line 95
    .line 96
    .line 97
    move-result-wide v6

    .line 98
    add-long/2addr v6, p0

    .line 99
    iput v5, v0, Ls50/f0;->f:I

    .line 100
    .line 101
    check-cast v4, Lp50/i;

    .line 102
    .line 103
    iget-object p0, v4, Lp50/i;->a:Lve0/u;

    .line 104
    .line 105
    const-string p1, "PREF_DIGITAL_CARD_NEXT_SHOW_DATE"

    .line 106
    .line 107
    invoke-virtual {p0, p1, v6, v7, v0}, Lve0/u;->m(Ljava/lang/String;JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    if-ne p0, v1, :cond_6

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_6
    move-object p0, v3

    .line 115
    :goto_3
    if-ne p0, v1, :cond_7

    .line 116
    .line 117
    :goto_4
    return-object v1

    .line 118
    :cond_7
    return-object v3
.end method
