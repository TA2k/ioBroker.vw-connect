.class public final synthetic Lb0/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/x1;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb0/q0;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lb0/q0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lh0/z1;)V
    .locals 8

    .line 1
    iget v0, p0, Lb0/q0;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lb0/q0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lu/x0;

    .line 9
    .line 10
    invoke-virtual {p0}, Lu/x0;->e()Lh0/z1;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 15
    .line 16
    iget-object p0, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lu/p;

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    iget-object v1, p0, Lu/p;->e:Lu/y;

    .line 23
    .line 24
    :try_start_0
    new-instance p0, Lu/p;

    .line 25
    .line 26
    const/4 p1, 0x3

    .line 27
    invoke-direct {p0, v1, p1}, Lu/p;-><init>(Lu/y;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 35
    .line 36
    invoke-virtual {p0}, Ly4/g;->get()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 43
    .line 44
    .line 45
    move-result p0
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    if-nez p0, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    iget-object p0, v1, Lu/y;->D:Lu/x0;

    .line 50
    .line 51
    iget-object p1, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v3, p1

    .line 54
    check-cast v3, Lh0/z1;

    .line 55
    .line 56
    iget-object p1, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v4, p1

    .line 59
    check-cast v4, Lu/w0;

    .line 60
    .line 61
    invoke-static {p0}, Lu/y;->z(Lu/x0;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    sget-object p0, Lh0/q2;->i:Lh0/q2;

    .line 66
    .line 67
    invoke-static {p0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    iget-object p0, v1, Lu/y;->f:Lj0/h;

    .line 72
    .line 73
    new-instance v0, Lu/s;

    .line 74
    .line 75
    const/4 v7, 0x2

    .line 76
    const/4 v5, 0x0

    .line 77
    invoke-direct/range {v0 .. v7}, Lu/s;-><init>(Lu/y;Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0, v0}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :catch_0
    move-exception v0

    .line 85
    move-object p0, v0

    .line 86
    new-instance p1, Ljava/lang/RuntimeException;

    .line 87
    .line 88
    const-string v0, "Unable to check if MeteringRepeating is attached."

    .line 89
    .line 90
    invoke-direct {p1, v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 91
    .line 92
    .line 93
    throw p1

    .line 94
    :cond_1
    :goto_0
    return-void

    .line 95
    :pswitch_0
    check-cast p0, Lh0/y1;

    .line 96
    .line 97
    iget-object p0, p0, Lh0/y1;->n:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    if-eqz v0, :cond_2

    .line 108
    .line 109
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    check-cast v0, Lh0/x1;

    .line 114
    .line 115
    invoke-interface {v0, p1}, Lh0/x1;->a(Lh0/z1;)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_2
    return-void

    .line 120
    :pswitch_1
    check-cast p0, Lb0/k1;

    .line 121
    .line 122
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    if-nez p1, :cond_3

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_3
    iget-object p1, p0, Lb0/z1;->g:Lh0/o2;

    .line 130
    .line 131
    check-cast p1, Lh0/o1;

    .line 132
    .line 133
    iget-object v0, p0, Lb0/z1;->h:Lh0/k;

    .line 134
    .line 135
    invoke-virtual {p0, p1, v0}, Lb0/k1;->F(Lh0/o1;Lh0/k;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0}, Lb0/z1;->p()V

    .line 139
    .line 140
    .line 141
    :goto_2
    return-void

    .line 142
    :pswitch_2
    check-cast p0, Lb0/u0;

    .line 143
    .line 144
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    if-nez p1, :cond_4

    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_4
    iget-object p1, p0, Lb0/u0;->v:Lg0/e;

    .line 152
    .line 153
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    invoke-static {}, Llp/k1;->a()V

    .line 157
    .line 158
    .line 159
    const/4 v0, 0x1

    .line 160
    iput-boolean v0, p1, Lg0/e;->g:Z

    .line 161
    .line 162
    invoke-virtual {p0, v0}, Lb0/u0;->D(Z)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0}, Lb0/z1;->e()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    iget-object v1, p0, Lb0/z1;->g:Lh0/o2;

    .line 170
    .line 171
    check-cast v1, Lh0/y0;

    .line 172
    .line 173
    iget-object v2, p0, Lb0/z1;->h:Lh0/k;

    .line 174
    .line 175
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    invoke-virtual {p0, p1, v1, v2}, Lb0/u0;->E(Ljava/lang/String;Lh0/y0;Lh0/k;)Lh0/v1;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    iput-object p1, p0, Lb0/u0;->t:Lh0/v1;

    .line 183
    .line 184
    invoke-virtual {p1}, Lh0/v1;->c()Lh0/z1;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    new-instance v1, Ljava/util/ArrayList;

    .line 193
    .line 194
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 195
    .line 196
    .line 197
    const/4 v0, 0x0

    .line 198
    aget-object p1, p1, v0

    .line 199
    .line 200
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 207
    .line 208
    .line 209
    move-result-object p1

    .line 210
    invoke-virtual {p0, p1}, Lb0/z1;->C(Ljava/util/List;)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {p0}, Lb0/z1;->p()V

    .line 214
    .line 215
    .line 216
    iget-object p0, p0, Lb0/u0;->v:Lg0/e;

    .line 217
    .line 218
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    invoke-static {}, Llp/k1;->a()V

    .line 222
    .line 223
    .line 224
    iput-boolean v0, p0, Lg0/e;->g:Z

    .line 225
    .line 226
    invoke-virtual {p0}, Lg0/e;->c()V

    .line 227
    .line 228
    .line 229
    :goto_3
    return-void

    .line 230
    nop

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
