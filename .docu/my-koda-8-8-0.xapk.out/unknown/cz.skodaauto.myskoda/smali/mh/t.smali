.class public final Lmh/t;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyy0/c2;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 6

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lmh/u;

    .line 5
    .line 6
    new-instance v1, Lc2/k;

    .line 7
    .line 8
    const/16 v2, 0x11

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, v2, v3}, Lc2/k;-><init>(IZ)V

    .line 12
    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-direct {v0, v1, v2, v2}, Lmh/u;-><init>(Lc2/k;ZZ)V

    .line 16
    .line 17
    .line 18
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iput-object v0, p0, Lmh/t;->d:Lyy0/c2;

    .line 23
    .line 24
    new-instance v1, Lag/r;

    .line 25
    .line 26
    const/4 v2, 0x7

    .line 27
    invoke-direct {v1, v0, v2}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Lmh/u;

    .line 39
    .line 40
    new-instance v3, Lmh/r;

    .line 41
    .line 42
    iget-object v4, v0, Lmh/u;->a:Lc2/k;

    .line 43
    .line 44
    iget-object v4, v4, Lc2/k;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v4, Lvp/y1;

    .line 47
    .line 48
    if-eqz v4, :cond_0

    .line 49
    .line 50
    iget-object v4, v4, Lvp/y1;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v4, Lmh/j;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    sget-object v4, Lmh/i;->b:Lmh/i;

    .line 56
    .line 57
    :goto_0
    iget-boolean v5, v0, Lmh/u;->b:Z

    .line 58
    .line 59
    iget-boolean v0, v0, Lmh/u;->c:Z

    .line 60
    .line 61
    invoke-direct {v3, v4, v5, v0}, Lmh/r;-><init>(Lmh/j;ZZ)V

    .line 62
    .line 63
    .line 64
    sget-object v0, Lyy0/u1;->a:Lyy0/w1;

    .line 65
    .line 66
    invoke-static {v1, v2, v0, v3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iput-object v0, p0, Lmh/t;->e:Lyy0/l1;

    .line 71
    .line 72
    return-void
.end method

.method public static a(Lyy0/j1;Lmh/j;)V
    .locals 7

    .line 1
    :cond_0
    move-object v0, p0

    .line 2
    check-cast v0, Lyy0/c2;

    .line 3
    .line 4
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    move-object v2, v1

    .line 9
    check-cast v2, Lmh/u;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    check-cast v3, Lmh/u;

    .line 16
    .line 17
    iget-object v3, v3, Lmh/u;->a:Lc2/k;

    .line 18
    .line 19
    iget-boolean v4, p1, Lmh/j;->a:Z

    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    if-nez v4, :cond_1

    .line 23
    .line 24
    new-instance v4, Lvp/y1;

    .line 25
    .line 26
    const/4 v6, 0x6

    .line 27
    invoke-direct {v4, p1, v5, v6}, Lvp/y1;-><init>(Lmh/j;Lvp/y1;I)V

    .line 28
    .line 29
    .line 30
    iput-object v4, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 31
    .line 32
    iput-object v4, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 33
    .line 34
    new-instance v3, Lc2/k;

    .line 35
    .line 36
    const/16 v5, 0x11

    .line 37
    .line 38
    const/4 v6, 0x0

    .line 39
    invoke-direct {v3, v5, v6}, Lc2/k;-><init>(IZ)V

    .line 40
    .line 41
    .line 42
    iput-object v4, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 43
    .line 44
    iput-object v4, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    iget-object v4, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v4, Lvp/y1;

    .line 50
    .line 51
    if-eqz v4, :cond_2

    .line 52
    .line 53
    iget-object v6, v4, Lvp/y1;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v6, Lvp/y1;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    move-object v6, v5

    .line 59
    :goto_0
    if-eqz v6, :cond_7

    .line 60
    .line 61
    if-eqz v4, :cond_3

    .line 62
    .line 63
    iget-object v4, v4, Lvp/y1;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v4, Lvp/y1;

    .line 66
    .line 67
    if-eqz v4, :cond_3

    .line 68
    .line 69
    iget-object v4, v4, Lvp/y1;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v4, Lmh/j;

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    move-object v4, v5

    .line 75
    :goto_1
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_6

    .line 80
    .line 81
    iget-object v4, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v4, Lvp/y1;

    .line 84
    .line 85
    if-nez v4, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    iget-object v4, v4, Lvp/y1;->f:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v4, Lvp/y1;

    .line 91
    .line 92
    iput-object v4, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 93
    .line 94
    if-eqz v4, :cond_5

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_5
    iput-object v5, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_6
    invoke-virtual {v3, p1}, Lc2/k;->n(Lmh/j;)V

    .line 101
    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_7
    invoke-virtual {v3, p1}, Lc2/k;->n(Lmh/j;)V

    .line 105
    .line 106
    .line 107
    :goto_2
    new-instance v4, Lc2/k;

    .line 108
    .line 109
    const/16 v5, 0x11

    .line 110
    .line 111
    const/4 v6, 0x0

    .line 112
    invoke-direct {v4, v5, v6}, Lc2/k;-><init>(IZ)V

    .line 113
    .line 114
    .line 115
    iget-object v5, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v5, Lvp/y1;

    .line 118
    .line 119
    iput-object v5, v4, Lc2/k;->e:Ljava/lang/Object;

    .line 120
    .line 121
    iget-object v3, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v3, Lvp/y1;

    .line 124
    .line 125
    iput-object v3, v4, Lc2/k;->f:Ljava/lang/Object;

    .line 126
    .line 127
    move-object v3, v4

    .line 128
    :goto_3
    const/16 v4, 0xe

    .line 129
    .line 130
    invoke-static {v2, v3, v4}, Lmh/u;->a(Lmh/u;Lc2/k;I)Lmh/u;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    if-eqz v0, :cond_0

    .line 139
    .line 140
    return-void
.end method


# virtual methods
.method public final b(Lmh/q;)V
    .locals 6

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmh/m;->a:Lmh/m;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x7

    .line 13
    const/4 v2, 0x0

    .line 14
    iget-object p0, p0, Lmh/t;->d:Lyy0/c2;

    .line 15
    .line 16
    if-eqz v0, :cond_5

    .line 17
    .line 18
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lmh/u;

    .line 23
    .line 24
    iget-object p1, p1, Lmh/u;->a:Lc2/k;

    .line 25
    .line 26
    iget-object p1, p1, Lc2/k;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p1, Lvp/y1;

    .line 29
    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    iget-object p1, p1, Lvp/y1;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Lmh/j;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    sget-object p1, Lmh/i;->b:Lmh/i;

    .line 38
    .line 39
    :goto_0
    iget-boolean p1, p1, Lmh/j;->a:Z

    .line 40
    .line 41
    const/4 v0, 0x1

    .line 42
    if-ne p1, v0, :cond_4

    .line 43
    .line 44
    :cond_1
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    move-object v0, p1

    .line 49
    check-cast v0, Lmh/u;

    .line 50
    .line 51
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Lmh/u;

    .line 56
    .line 57
    iget-object v1, v1, Lmh/u;->a:Lc2/k;

    .line 58
    .line 59
    iget-object v3, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v3, Lvp/y1;

    .line 62
    .line 63
    if-nez v3, :cond_2

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    iget-object v3, v3, Lvp/y1;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v3, Lvp/y1;

    .line 69
    .line 70
    iput-object v3, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 71
    .line 72
    if-eqz v3, :cond_3

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    iput-object v2, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 76
    .line 77
    :goto_1
    new-instance v3, Lc2/k;

    .line 78
    .line 79
    const/16 v4, 0x11

    .line 80
    .line 81
    const/4 v5, 0x0

    .line 82
    invoke-direct {v3, v4, v5}, Lc2/k;-><init>(IZ)V

    .line 83
    .line 84
    .line 85
    iget-object v4, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v4, Lvp/y1;

    .line 88
    .line 89
    iput-object v4, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 90
    .line 91
    iget-object v1, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v1, Lvp/y1;

    .line 94
    .line 95
    iput-object v1, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 96
    .line 97
    const/16 v1, 0xe

    .line 98
    .line 99
    invoke-static {v0, v3, v1}, Lmh/u;->a(Lmh/u;Lc2/k;I)Lmh/u;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result p1

    .line 107
    if-eqz p1, :cond_1

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    move-object v0, p1

    .line 115
    check-cast v0, Lmh/u;

    .line 116
    .line 117
    invoke-static {v0, v2, v1}, Lmh/u;->a(Lmh/u;Lc2/k;I)Lmh/u;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    if-eqz p1, :cond_4

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_5
    sget-object v0, Lmh/n;->a:Lmh/n;

    .line 129
    .line 130
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_7

    .line 135
    .line 136
    :cond_6
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    move-object v0, p1

    .line 141
    check-cast v0, Lmh/u;

    .line 142
    .line 143
    invoke-static {v0, v2, v1}, Lmh/u;->a(Lmh/u;Lc2/k;I)Lmh/u;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    if-eqz p1, :cond_6

    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_7
    sget-object v0, Lmh/o;->a:Lmh/o;

    .line 155
    .line 156
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v0

    .line 160
    if-eqz v0, :cond_9

    .line 161
    .line 162
    :cond_8
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    move-object v0, p1

    .line 167
    check-cast v0, Lmh/u;

    .line 168
    .line 169
    const/16 v1, 0xb

    .line 170
    .line 171
    invoke-static {v0, v2, v1}, Lmh/u;->a(Lmh/u;Lc2/k;I)Lmh/u;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result p1

    .line 179
    if-eqz p1, :cond_8

    .line 180
    .line 181
    :goto_2
    return-void

    .line 182
    :cond_9
    instance-of v0, p1, Lmh/p;

    .line 183
    .line 184
    if-eqz v0, :cond_a

    .line 185
    .line 186
    check-cast p1, Lmh/p;

    .line 187
    .line 188
    iget-object p1, p1, Lmh/p;->a:Lmh/j;

    .line 189
    .line 190
    invoke-static {p0, p1}, Lmh/t;->a(Lyy0/j1;Lmh/j;)V

    .line 191
    .line 192
    .line 193
    return-void

    .line 194
    :cond_a
    new-instance p0, La8/r0;

    .line 195
    .line 196
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 197
    .line 198
    .line 199
    throw p0
.end method
