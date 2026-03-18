.class public final Lf50/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# static fields
.field public static final d:Lhl0/b;


# instance fields
.field public final a:Lpp0/b1;

.field public final b:Lgl0/e;

.field public final c:Lpp0/r1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget-object v0, Lhl0/a;->f:Lhl0/a;

    .line 2
    .line 3
    new-instance v1, Lhl0/b;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/16 v3, 0x51c

    .line 7
    .line 8
    invoke-direct {v1, v2, v0, v3}, Lhl0/b;-><init>(ZLhl0/a;I)V

    .line 9
    .line 10
    .line 11
    sput-object v1, Lf50/g;->d:Lhl0/b;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lpp0/b1;Lgl0/e;Lpp0/r1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/g;->a:Lpp0/b1;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/g;->b:Lgl0/e;

    .line 7
    .line 8
    iput-object p3, p0, Lf50/g;->c:Lpp0/r1;

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
    invoke-virtual {p0, p2}, Lf50/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lf50/g;->a:Lpp0/b1;

    .line 2
    .line 3
    iget-object v0, v0, Lpp0/b1;->a:Lpp0/c0;

    .line 4
    .line 5
    instance-of v1, p1, Lf50/f;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lf50/f;

    .line 11
    .line 12
    iget v2, v1, Lf50/f;->g:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lf50/f;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lf50/f;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lf50/f;-><init>(Lf50/g;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v1, Lf50/f;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lf50/f;->g:I

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    if-eqz v3, :cond_3

    .line 38
    .line 39
    if-eq v3, v5, :cond_2

    .line 40
    .line 41
    if-ne v3, v4, :cond_1

    .line 42
    .line 43
    iget-object p0, v1, Lf50/f;->d:Lhl0/i;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto/16 :goto_4

    .line 49
    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object p1, v0

    .line 66
    check-cast p1, Lnp0/b;

    .line 67
    .line 68
    iput-boolean v5, p1, Lnp0/b;->a:Z

    .line 69
    .line 70
    iput v5, v1, Lf50/f;->g:I

    .line 71
    .line 72
    iget-object p1, p0, Lf50/g;->b:Lgl0/e;

    .line 73
    .line 74
    sget-object v3, Lf50/g;->d:Lhl0/b;

    .line 75
    .line 76
    invoke-virtual {p1, v3, v1}, Lgl0/e;->b(Lhl0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    if-ne p1, v2, :cond_4

    .line 81
    .line 82
    goto/16 :goto_3

    .line 83
    .line 84
    :cond_4
    :goto_1
    check-cast p1, Lhl0/i;

    .line 85
    .line 86
    if-eqz p1, :cond_c

    .line 87
    .line 88
    instance-of v3, p1, Lhl0/c;

    .line 89
    .line 90
    if-eqz v3, :cond_5

    .line 91
    .line 92
    new-instance v3, Lqp0/t;

    .line 93
    .line 94
    move-object v5, p1

    .line 95
    check-cast v5, Lhl0/c;

    .line 96
    .line 97
    iget-object v5, v5, Lhl0/c;->a:Lxj0/f;

    .line 98
    .line 99
    invoke-direct {v3, v5}, Lqp0/t;-><init>(Lxj0/f;)V

    .line 100
    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_5
    instance-of v3, p1, Lhl0/f;

    .line 104
    .line 105
    if-eqz v3, :cond_6

    .line 106
    .line 107
    new-instance v3, Lqp0/v;

    .line 108
    .line 109
    move-object v5, p1

    .line 110
    check-cast v5, Lhl0/f;

    .line 111
    .line 112
    iget-object v6, v5, Lhl0/f;->a:Ljava/lang/String;

    .line 113
    .line 114
    iget-object v5, v5, Lhl0/f;->b:Ljava/lang/String;

    .line 115
    .line 116
    invoke-direct {v3, v6, v5}, Lqp0/v;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_6
    instance-of v3, p1, Lhl0/h;

    .line 121
    .line 122
    if-eqz v3, :cond_7

    .line 123
    .line 124
    new-instance v3, Lqp0/w;

    .line 125
    .line 126
    move-object v5, p1

    .line 127
    check-cast v5, Lhl0/h;

    .line 128
    .line 129
    iget-object v5, v5, Lhl0/h;->a:Lxj0/f;

    .line 130
    .line 131
    invoke-direct {v3, v5}, Lqp0/w;-><init>(Lxj0/f;)V

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_7
    instance-of v3, p1, Lhl0/e;

    .line 136
    .line 137
    if-eqz v3, :cond_8

    .line 138
    .line 139
    new-instance v3, Lqp0/u;

    .line 140
    .line 141
    move-object v5, p1

    .line 142
    check-cast v5, Lhl0/e;

    .line 143
    .line 144
    iget-object v5, v5, Lhl0/e;->a:Lxj0/f;

    .line 145
    .line 146
    invoke-direct {v3, v5}, Lqp0/u;-><init>(Lxj0/f;)V

    .line 147
    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_8
    instance-of v3, p1, Lhl0/d;

    .line 151
    .line 152
    if-eqz v3, :cond_9

    .line 153
    .line 154
    new-instance v3, Lqp0/v;

    .line 155
    .line 156
    move-object v5, p1

    .line 157
    check-cast v5, Lhl0/d;

    .line 158
    .line 159
    iget-object v5, v5, Lhl0/d;->a:Lmk0/a;

    .line 160
    .line 161
    iget-object v6, v5, Lmk0/a;->c:Ljava/lang/String;

    .line 162
    .line 163
    iget-object v5, v5, Lmk0/a;->e:Ljava/lang/String;

    .line 164
    .line 165
    invoke-direct {v3, v6, v5}, Lqp0/v;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_9
    instance-of v3, p1, Lhl0/g;

    .line 170
    .line 171
    if-eqz v3, :cond_b

    .line 172
    .line 173
    new-instance v3, Lqp0/v;

    .line 174
    .line 175
    move-object v5, p1

    .line 176
    check-cast v5, Lhl0/g;

    .line 177
    .line 178
    iget-object v5, v5, Lhl0/g;->a:Lbl0/g0;

    .line 179
    .line 180
    invoke-interface {v5}, Lbl0/g0;->getId()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v6

    .line 184
    invoke-interface {v5}, Lbl0/g0;->getName()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    invoke-direct {v3, v6, v5}, Lqp0/v;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    :goto_2
    iput-object p1, v1, Lf50/f;->d:Lhl0/i;

    .line 192
    .line 193
    iput v4, v1, Lf50/f;->g:I

    .line 194
    .line 195
    iget-object p0, p0, Lf50/g;->c:Lpp0/r1;

    .line 196
    .line 197
    invoke-virtual {p0, v3, v1}, Lpp0/r1;->b(Lqp0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    if-ne p0, v2, :cond_a

    .line 202
    .line 203
    :goto_3
    return-object v2

    .line 204
    :cond_a
    move-object p0, p1

    .line 205
    :goto_4
    move-object p1, p0

    .line 206
    goto :goto_5

    .line 207
    :cond_b
    new-instance p0, La8/r0;

    .line 208
    .line 209
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 210
    .line 211
    .line 212
    throw p0

    .line 213
    :cond_c
    :goto_5
    check-cast v0, Lnp0/b;

    .line 214
    .line 215
    const/4 p0, 0x0

    .line 216
    iput-boolean p0, v0, Lnp0/b;->a:Z

    .line 217
    .line 218
    return-object p1
.end method
