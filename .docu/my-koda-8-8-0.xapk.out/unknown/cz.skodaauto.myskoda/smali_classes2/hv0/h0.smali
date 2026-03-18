.class public final Lhv0/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ll50/p0;

.field public final b:Lhv0/z;

.field public final c:Lal0/o1;

.field public final d:Lwj0/f;


# direct methods
.method public constructor <init>(Ll50/p0;Lhv0/z;Lal0/o1;Lwj0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/h0;->a:Ll50/p0;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/h0;->b:Lhv0/z;

    .line 7
    .line 8
    iput-object p3, p0, Lhv0/h0;->c:Lal0/o1;

    .line 9
    .line 10
    iput-object p4, p0, Lhv0/h0;->d:Lwj0/f;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Liv0/f;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lhv0/h0;->b(Liv0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Liv0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lhv0/g0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lhv0/g0;

    .line 7
    .line 8
    iget v1, v0, Lhv0/g0;->g:I

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
    iput v1, v0, Lhv0/g0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhv0/g0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lhv0/g0;-><init>(Lhv0/h0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lhv0/g0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhv0/g0;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v5, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v3

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    iget-object p1, v0, Lhv0/g0;->d:Liv0/f;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object p2, p0, Lhv0/h0;->d:Lwj0/f;

    .line 64
    .line 65
    invoke-virtual {p2}, Lwj0/f;->invoke()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    sget-object p2, Liv0/n;->a:Liv0/n;

    .line 69
    .line 70
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    if-nez p2, :cond_4

    .line 75
    .line 76
    iput-object p1, v0, Lhv0/g0;->d:Liv0/f;

    .line 77
    .line 78
    iput v5, v0, Lhv0/g0;->g:I

    .line 79
    .line 80
    iget-object p2, p0, Lhv0/h0;->a:Ll50/p0;

    .line 81
    .line 82
    iget-object p2, p2, Ll50/p0;->a:Lal0/m1;

    .line 83
    .line 84
    invoke-virtual {p2, v6}, Lal0/m1;->a(Lbl0/j0;)V

    .line 85
    .line 86
    .line 87
    if-ne v3, v1, :cond_4

    .line 88
    .line 89
    goto/16 :goto_3

    .line 90
    .line 91
    :cond_4
    :goto_1
    iget-object p2, p0, Lhv0/h0;->b:Lhv0/z;

    .line 92
    .line 93
    check-cast p2, Lfv0/c;

    .line 94
    .line 95
    const-string v2, "mapFeature"

    .line 96
    .line 97
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    iget-object p2, p2, Lfv0/c;->a:Lyy0/c2;

    .line 101
    .line 102
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    invoke-virtual {p2, v6, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    sget-object p2, Liv0/a;->a:Liv0/a;

    .line 109
    .line 110
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    if-eqz p2, :cond_5

    .line 115
    .line 116
    sget-object p1, Lbl0/h0;->d:Lbl0/h0;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    sget-object p2, Liv0/c;->a:Liv0/c;

    .line 120
    .line 121
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    if-eqz p2, :cond_6

    .line 126
    .line 127
    sget-object p1, Lbl0/h0;->e:Lbl0/h0;

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_6
    sget-object p2, Liv0/i;->a:Liv0/i;

    .line 131
    .line 132
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result p2

    .line 136
    if-eqz p2, :cond_7

    .line 137
    .line 138
    sget-object p1, Lbl0/h0;->g:Lbl0/h0;

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_7
    sget-object p2, Liv0/h;->a:Liv0/h;

    .line 142
    .line 143
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    if-eqz p2, :cond_8

    .line 148
    .line 149
    sget-object p1, Lbl0/h0;->h:Lbl0/h0;

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_8
    sget-object p2, Liv0/m;->a:Liv0/m;

    .line 153
    .line 154
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    if-eqz p2, :cond_9

    .line 159
    .line 160
    sget-object p1, Lbl0/h0;->i:Lbl0/h0;

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_9
    sget-object p2, Liv0/u;->a:Liv0/u;

    .line 164
    .line 165
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result p2

    .line 169
    if-eqz p2, :cond_a

    .line 170
    .line 171
    sget-object p1, Lbl0/h0;->k:Lbl0/h0;

    .line 172
    .line 173
    goto :goto_2

    .line 174
    :cond_a
    sget-object p2, Liv0/d;->a:Liv0/d;

    .line 175
    .line 176
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p1

    .line 180
    if-eqz p1, :cond_b

    .line 181
    .line 182
    sget-object p1, Lbl0/h0;->j:Lbl0/h0;

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_b
    move-object p1, v6

    .line 186
    :goto_2
    iput-object v6, v0, Lhv0/g0;->d:Liv0/f;

    .line 187
    .line 188
    iput v4, v0, Lhv0/g0;->g:I

    .line 189
    .line 190
    iget-object p0, p0, Lhv0/h0;->c:Lal0/o1;

    .line 191
    .line 192
    invoke-virtual {p0, p1, v0}, Lal0/o1;->b(Lbl0/h0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    if-ne p0, v1, :cond_c

    .line 197
    .line 198
    :goto_3
    return-object v1

    .line 199
    :cond_c
    return-object v3
.end method
