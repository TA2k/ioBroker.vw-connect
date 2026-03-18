.class public abstract Lw11/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lvd/i;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lvd/i;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lw11/c;->a:Ll2/e0;

    .line 14
    .line 15
    new-instance v0, Lvd/i;

    .line 16
    .line 17
    const/16 v1, 0xe

    .line 18
    .line 19
    invoke-direct {v0, v1}, Lvd/i;-><init>(I)V

    .line 20
    .line 21
    .line 22
    new-instance v1, Ll2/e0;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 25
    .line 26
    .line 27
    sput-object v1, Lw11/c;->b:Ll2/e0;

    .line 28
    .line 29
    return-void
.end method

.method public static final a(Lx11/a;Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lx11/a;->a:Landroidx/lifecycle/c1;

    .line 7
    .line 8
    check-cast p2, Ll2/t;

    .line 9
    .line 10
    const v1, -0x63b6fa57

    .line 11
    .line 12
    .line 13
    invoke-virtual {p2, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 14
    .line 15
    .line 16
    and-int/lit8 v1, p3, 0x6

    .line 17
    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    const/4 v1, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v1, 0x2

    .line 29
    :goto_0
    or-int/2addr v1, p3

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v1, p3

    .line 32
    :goto_1
    and-int/lit8 v2, p3, 0x30

    .line 33
    .line 34
    if-nez v2, :cond_3

    .line 35
    .line 36
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_2

    .line 41
    .line 42
    const/16 v2, 0x20

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/16 v2, 0x10

    .line 46
    .line 47
    :goto_2
    or-int/2addr v1, v2

    .line 48
    :cond_3
    and-int/lit8 v2, v1, 0x13

    .line 49
    .line 50
    const/16 v3, 0x12

    .line 51
    .line 52
    if-ne v2, v3, :cond_5

    .line 53
    .line 54
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-nez v2, :cond_4

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    goto :goto_4

    .line 65
    :cond_5
    :goto_3
    const v2, 0x4c5de2

    .line 66
    .line 67
    .line 68
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 80
    .line 81
    if-nez v3, :cond_6

    .line 82
    .line 83
    if-ne v4, v5, :cond_7

    .line 84
    .line 85
    :cond_6
    new-instance v4, Lw11/b;

    .line 86
    .line 87
    const/4 v3, 0x0

    .line 88
    invoke-direct {v4, p0, v3}, Lw11/b;-><init>(Lx11/a;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_7
    check-cast v4, Lay0/a;

    .line 95
    .line 96
    const/4 v3, 0x0

    .line 97
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 98
    .line 99
    .line 100
    new-instance v6, Lw11/a;

    .line 101
    .line 102
    invoke-direct {v6, v0, v4}, Lw11/a;-><init>(Ljava/lang/Object;Lay0/a;)V

    .line 103
    .line 104
    .line 105
    sget-object v4, Lw11/c;->a:Ll2/e0;

    .line 106
    .line 107
    invoke-virtual {v4, v6}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    iget-object v0, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Li21/b;

    .line 114
    .line 115
    iget-object v0, v0, Li21/b;->d:Lk21/a;

    .line 116
    .line 117
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    if-nez v2, :cond_8

    .line 129
    .line 130
    if-ne v6, v5, :cond_9

    .line 131
    .line 132
    :cond_8
    new-instance v6, Lw11/b;

    .line 133
    .line 134
    const/4 v2, 0x1

    .line 135
    invoke-direct {v6, p0, v2}, Lw11/b;-><init>(Lx11/a;I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p2, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_9
    check-cast v6, Lay0/a;

    .line 142
    .line 143
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 144
    .line 145
    .line 146
    new-instance v2, Lw11/a;

    .line 147
    .line 148
    invoke-direct {v2, v0, v6}, Lw11/a;-><init>(Ljava/lang/Object;Lay0/a;)V

    .line 149
    .line 150
    .line 151
    sget-object v0, Lw11/c;->b:Ll2/e0;

    .line 152
    .line 153
    invoke-virtual {v0, v2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    filled-new-array {v4, v0}, [Ll2/t1;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    and-int/lit8 v1, v1, 0x70

    .line 162
    .line 163
    const/16 v2, 0x8

    .line 164
    .line 165
    or-int/2addr v1, v2

    .line 166
    invoke-static {v0, p1, p2, v1}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 167
    .line 168
    .line 169
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 170
    .line 171
    .line 172
    move-result-object p2

    .line 173
    if-eqz p2, :cond_a

    .line 174
    .line 175
    new-instance v0, Ltj/i;

    .line 176
    .line 177
    const/16 v1, 0xf

    .line 178
    .line 179
    invoke-direct {v0, p3, v1, p0, p1}, Ltj/i;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 183
    .line 184
    :cond_a
    return-void
.end method

.method public static final b(Ll2/o;)Lk21/a;
    .locals 4

    .line 1
    sget-object v0, Lw11/c;->b:Ll2/e0;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    const v1, 0x6378e4a6

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v1}, Ll2/t;->Y(I)V

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    :try_start_0
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    check-cast v2, Lw11/a;

    .line 17
    .line 18
    iget-object v3, v2, Lw11/a;->b:Ljava/lang/Object;

    .line 19
    .line 20
    if-nez v3, :cond_1

    .line 21
    .line 22
    iget-object v3, v2, Lw11/a;->a:Lay0/a;

    .line 23
    .line 24
    if-eqz v3, :cond_0

    .line 25
    .line 26
    invoke-interface {v3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move-object v3, v1

    .line 32
    :goto_0
    iput-object v3, v2, Lw11/a;->b:Ljava/lang/Object;

    .line 33
    .line 34
    :cond_1
    iget-object v2, v2, Lw11/a;->b:Ljava/lang/Object;

    .line 35
    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    check-cast v2, Lk21/a;

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :catch_0
    move-exception v2

    .line 42
    goto :goto_1

    .line 43
    :cond_2
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string v3, "Can\'t retrieve value for "

    .line 46
    .line 47
    invoke-direct {v2, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw v2
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 51
    :goto_1
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    check-cast v0, Lw11/a;

    .line 56
    .line 57
    iget-object v3, v0, Lw11/a;->a:Lay0/a;

    .line 58
    .line 59
    if-eqz v3, :cond_3

    .line 60
    .line 61
    invoke-interface {v3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    :cond_3
    iput-object v1, v0, Lw11/a;->b:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v0, v1

    .line 68
    check-cast v0, Lk21/a;

    .line 69
    .line 70
    if-eqz v0, :cond_4

    .line 71
    .line 72
    move-object v2, v0

    .line 73
    :goto_2
    const/4 v0, 0x0

    .line 74
    invoke-virtual {p0, v0}, Ll2/t;->q(Z)V

    .line 75
    .line 76
    .line 77
    return-object v2

    .line 78
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    new-instance v0, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    const-string v1, "Can\'t get Koin scope due to error: "

    .line 83
    .line 84
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0
.end method
