.class public final Lv31/b;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Lk31/n;

.field public final h:Lk31/u;

.field public final i:Lk31/k0;

.field public final j:Landroidx/lifecycle/s0;


# direct methods
.method public constructor <init>(Lz9/y;Lk31/n;Lk31/u;Lk31/k0;Landroidx/lifecycle/s0;)V
    .locals 2

    .line 1
    new-instance v0, Lv31/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lv31/c;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lq41/b;-><init>(Lq41/a;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lv31/b;->f:Lz9/y;

    .line 11
    .line 12
    iput-object p2, p0, Lv31/b;->g:Lk31/n;

    .line 13
    .line 14
    iput-object p3, p0, Lv31/b;->h:Lk31/u;

    .line 15
    .line 16
    iput-object p4, p0, Lv31/b;->i:Lk31/k0;

    .line 17
    .line 18
    iput-object p5, p0, Lv31/b;->j:Landroidx/lifecycle/s0;

    .line 19
    .line 20
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    new-instance p2, Ltr0/e;

    .line 25
    .line 26
    const/16 p3, 0x12

    .line 27
    .line 28
    const/4 p4, 0x0

    .line 29
    invoke-direct {p2, p0, p4, p3}, Ltr0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x3

    .line 33
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public static final b(Lv31/b;Lv31/d;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lq41/b;->d:Lyy0/c2;

    .line 2
    .line 3
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Lv31/c;

    .line 9
    .line 10
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    new-instance v2, Lv31/c;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-direct {v2, v3}, Lv31/c;-><init>(Z)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    iget-object v0, p0, Lv31/b;->i:Lk31/k0;

    .line 26
    .line 27
    new-instance v4, Lk31/j0;

    .line 28
    .line 29
    iget-object v5, p1, Lv31/d;->a:Lz21/c;

    .line 30
    .line 31
    iget-object v6, p1, Lv31/d;->e:Lz21/e;

    .line 32
    .line 33
    iget-boolean v7, p1, Lv31/d;->b:Z

    .line 34
    .line 35
    iget-boolean v8, p1, Lv31/d;->c:Z

    .line 36
    .line 37
    iget p1, p1, Lv31/d;->d:I

    .line 38
    .line 39
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object v9

    .line 43
    invoke-direct/range {v4 .. v9}, Lk31/j0;-><init>(Lz21/c;Lz21/e;ZZLjava/lang/Integer;)V

    .line 44
    .line 45
    .line 46
    iget-object p1, v0, Lk31/k0;->a:Lf31/h;

    .line 47
    .line 48
    new-instance v0, Li40/e1;

    .line 49
    .line 50
    const/16 v1, 0x10

    .line 51
    .line 52
    invoke-direct {v0, v4, v1}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    iget-object p1, p1, Lf31/h;->a:Lb31/a;

    .line 56
    .line 57
    invoke-virtual {p1, v0}, Lb31/a;->d(Lay0/k;)V

    .line 58
    .line 59
    .line 60
    sget-object p1, Lz21/c;->d:Lnm0/b;

    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    sget-object p1, Lz21/f;->b:Ljava/util/List;

    .line 66
    .line 67
    check-cast p1, Ljava/lang/Iterable;

    .line 68
    .line 69
    instance-of v0, p1, Ljava/util/Collection;

    .line 70
    .line 71
    if-eqz v0, :cond_2

    .line 72
    .line 73
    move-object v0, p1

    .line 74
    check-cast v0, Ljava/util/Collection;

    .line 75
    .line 76
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_2

    .line 81
    .line 82
    :cond_1
    move p1, v3

    .line 83
    goto :goto_0

    .line 84
    :cond_2
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    :cond_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_1

    .line 93
    .line 94
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    check-cast v0, Lz21/f;

    .line 99
    .line 100
    iget-object v0, v0, Lz21/f;->a:Lz21/c;

    .line 101
    .line 102
    if-ne v0, v5, :cond_3

    .line 103
    .line 104
    const/4 p1, 0x1

    .line 105
    :goto_0
    sget-object v0, La31/a;->b:La31/a;

    .line 106
    .line 107
    new-instance v1, Llx0/l;

    .line 108
    .line 109
    const-string v2, "platform"

    .line 110
    .line 111
    const-string v4, "Android"

    .line 112
    .line 113
    invoke-direct {v1, v2, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-static {p1}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    new-instance v2, Llx0/l;

    .line 121
    .line 122
    const-string v4, "sbo"

    .line 123
    .line 124
    invoke-direct {v2, v4, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    filled-new-array {v1, v2}, [Llx0/l;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    iget-boolean v0, v0, Lmh/j;->a:Z

    .line 132
    .line 133
    if-eqz v0, :cond_4

    .line 134
    .line 135
    sget-object v0, Ls41/b;->a:Lpw0/a;

    .line 136
    .line 137
    new-instance v0, Ls41/a;

    .line 138
    .line 139
    const/4 v1, 0x2

    .line 140
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    check-cast p1, [Llx0/l;

    .line 145
    .line 146
    const-string v1, "contextData"

    .line 147
    .line 148
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    sget-object v1, Ls41/c;->e:Ls41/c;

    .line 152
    .line 153
    array-length v2, p1

    .line 154
    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    check-cast p1, [Llx0/l;

    .line 159
    .line 160
    const-string v2, "CAT-AppointmentBooking-UserModuleAccess"

    .line 161
    .line 162
    invoke-direct {v0, v2, v1, p1}, Leb/j0;-><init>(Ljava/lang/String;Ls41/c;[Llx0/l;)V

    .line 163
    .line 164
    .line 165
    invoke-static {v0}, Ls41/b;->a(Leb/j0;)V

    .line 166
    .line 167
    .line 168
    :cond_4
    iget-object p0, p0, Lv31/b;->f:Lz9/y;

    .line 169
    .line 170
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 171
    .line 172
    .line 173
    move-result p1

    .line 174
    const/4 v0, 0x3

    .line 175
    if-eq p1, v0, :cond_5

    .line 176
    .line 177
    const/4 v0, 0x4

    .line 178
    if-eq p1, v0, :cond_5

    .line 179
    .line 180
    new-instance p1, Ll31/m;

    .line 181
    .line 182
    invoke-direct {p1, v3}, Ll31/m;-><init>(Z)V

    .line 183
    .line 184
    .line 185
    goto :goto_1

    .line 186
    :cond_5
    sget-object p1, Ll31/x;->INSTANCE:Ll31/x;

    .line 187
    .line 188
    :goto_1
    new-instance v0, Luu/r;

    .line 189
    .line 190
    const/16 v1, 0x1b

    .line 191
    .line 192
    invoke-direct {v0, v1}, Luu/r;-><init>(I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 196
    .line 197
    .line 198
    const-string v1, "route"

    .line 199
    .line 200
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 204
    .line 205
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    invoke-static {v0}, Ljp/r0;->d(Lay0/k;)Lz9/b0;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    invoke-virtual {p0, p1}, Lca/g;->f(Ljava/lang/Object;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    invoke-virtual {p0, p1, v0}, Lca/g;->m(Ljava/lang/String;Lz9/b0;)V

    .line 217
    .line 218
    .line 219
    return-void
.end method
