.class public final synthetic Lh2/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lk1/z0;

.field public final synthetic g:Z

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Ljava/lang/Object;

.field public final synthetic n:Ljava/lang/Object;

.field public final synthetic o:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lh2/q0;Le1/t;Lk1/z0;Lt2/b;II)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lh2/r0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/r0;->j:Ljava/lang/Object;

    iput-object p2, p0, Lh2/r0;->e:Lx2/s;

    iput-boolean p3, p0, Lh2/r0;->g:Z

    iput-object p4, p0, Lh2/r0;->k:Ljava/lang/Object;

    iput-object p5, p0, Lh2/r0;->l:Ljava/lang/Object;

    iput-object p6, p0, Lh2/r0;->m:Ljava/lang/Object;

    iput-object p7, p0, Lh2/r0;->n:Ljava/lang/Object;

    iput-object p8, p0, Lh2/r0;->f:Lk1/z0;

    iput-object p9, p0, Lh2/r0;->o:Llx0/e;

    iput p10, p0, Lh2/r0;->h:I

    iput p11, p0, Lh2/r0;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lm1/t;Lk1/z0;Ljava/lang/Object;Ljava/lang/Object;Lg1/j1;ZLe1/j;Lay0/k;III)V
    .locals 0

    .line 2
    iput p12, p0, Lh2/r0;->d:I

    iput-object p1, p0, Lh2/r0;->e:Lx2/s;

    iput-object p2, p0, Lh2/r0;->j:Ljava/lang/Object;

    iput-object p3, p0, Lh2/r0;->f:Lk1/z0;

    iput-object p4, p0, Lh2/r0;->k:Ljava/lang/Object;

    iput-object p5, p0, Lh2/r0;->l:Ljava/lang/Object;

    iput-object p6, p0, Lh2/r0;->m:Ljava/lang/Object;

    iput-boolean p7, p0, Lh2/r0;->g:Z

    iput-object p8, p0, Lh2/r0;->n:Ljava/lang/Object;

    iput-object p9, p0, Lh2/r0;->o:Llx0/e;

    iput p10, p0, Lh2/r0;->h:I

    iput p11, p0, Lh2/r0;->i:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lh2/r0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/r0;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Lm1/t;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/r0;->k:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lk1/i;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/r0;->l:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v5, v0

    .line 19
    check-cast v5, Lx2/d;

    .line 20
    .line 21
    iget-object v0, p0, Lh2/r0;->m:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v6, v0

    .line 24
    check-cast v6, Lg1/j1;

    .line 25
    .line 26
    iget-object v0, p0, Lh2/r0;->n:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v8, v0

    .line 29
    check-cast v8, Le1/j;

    .line 30
    .line 31
    iget-object v0, p0, Lh2/r0;->o:Llx0/e;

    .line 32
    .line 33
    move-object v9, v0

    .line 34
    check-cast v9, Lay0/k;

    .line 35
    .line 36
    move-object v10, p1

    .line 37
    check-cast v10, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget p1, p0, Lh2/r0;->h:I

    .line 45
    .line 46
    or-int/lit8 p1, p1, 0x1

    .line 47
    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v11

    .line 52
    iget-object v1, p0, Lh2/r0;->e:Lx2/s;

    .line 53
    .line 54
    iget-object v3, p0, Lh2/r0;->f:Lk1/z0;

    .line 55
    .line 56
    iget-boolean v7, p0, Lh2/r0;->g:Z

    .line 57
    .line 58
    iget v12, p0, Lh2/r0;->i:I

    .line 59
    .line 60
    invoke-static/range {v1 .. v12}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 61
    .line 62
    .line 63
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_0
    iget-object v0, p0, Lh2/r0;->j:Ljava/lang/Object;

    .line 67
    .line 68
    move-object v2, v0

    .line 69
    check-cast v2, Lm1/t;

    .line 70
    .line 71
    iget-object v0, p0, Lh2/r0;->k:Ljava/lang/Object;

    .line 72
    .line 73
    move-object v4, v0

    .line 74
    check-cast v4, Lk1/g;

    .line 75
    .line 76
    iget-object v0, p0, Lh2/r0;->l:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v5, v0

    .line 79
    check-cast v5, Lx2/i;

    .line 80
    .line 81
    iget-object v0, p0, Lh2/r0;->m:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v6, v0

    .line 84
    check-cast v6, Lg1/j1;

    .line 85
    .line 86
    iget-object v0, p0, Lh2/r0;->n:Ljava/lang/Object;

    .line 87
    .line 88
    move-object v8, v0

    .line 89
    check-cast v8, Le1/j;

    .line 90
    .line 91
    iget-object v0, p0, Lh2/r0;->o:Llx0/e;

    .line 92
    .line 93
    move-object v9, v0

    .line 94
    check-cast v9, Lay0/k;

    .line 95
    .line 96
    move-object v10, p1

    .line 97
    check-cast v10, Ll2/o;

    .line 98
    .line 99
    check-cast p2, Ljava/lang/Integer;

    .line 100
    .line 101
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 102
    .line 103
    .line 104
    iget p1, p0, Lh2/r0;->h:I

    .line 105
    .line 106
    or-int/lit8 p1, p1, 0x1

    .line 107
    .line 108
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 109
    .line 110
    .line 111
    move-result v11

    .line 112
    iget-object v1, p0, Lh2/r0;->e:Lx2/s;

    .line 113
    .line 114
    iget-object v3, p0, Lh2/r0;->f:Lk1/z0;

    .line 115
    .line 116
    iget-boolean v7, p0, Lh2/r0;->g:Z

    .line 117
    .line 118
    iget v12, p0, Lh2/r0;->i:I

    .line 119
    .line 120
    invoke-static/range {v1 .. v12}, La/a;->b(Lx2/s;Lm1/t;Lk1/z0;Lk1/g;Lx2/i;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 121
    .line 122
    .line 123
    goto :goto_0

    .line 124
    :pswitch_1
    iget-object v0, p0, Lh2/r0;->j:Ljava/lang/Object;

    .line 125
    .line 126
    move-object v1, v0

    .line 127
    check-cast v1, Lay0/a;

    .line 128
    .line 129
    iget-object v0, p0, Lh2/r0;->k:Ljava/lang/Object;

    .line 130
    .line 131
    move-object v4, v0

    .line 132
    check-cast v4, Le3/n0;

    .line 133
    .line 134
    iget-object v0, p0, Lh2/r0;->l:Ljava/lang/Object;

    .line 135
    .line 136
    move-object v5, v0

    .line 137
    check-cast v5, Lh2/n0;

    .line 138
    .line 139
    iget-object v0, p0, Lh2/r0;->m:Ljava/lang/Object;

    .line 140
    .line 141
    move-object v6, v0

    .line 142
    check-cast v6, Lh2/q0;

    .line 143
    .line 144
    iget-object v0, p0, Lh2/r0;->n:Ljava/lang/Object;

    .line 145
    .line 146
    move-object v7, v0

    .line 147
    check-cast v7, Le1/t;

    .line 148
    .line 149
    iget-object v0, p0, Lh2/r0;->o:Llx0/e;

    .line 150
    .line 151
    move-object v9, v0

    .line 152
    check-cast v9, Lt2/b;

    .line 153
    .line 154
    move-object v10, p1

    .line 155
    check-cast v10, Ll2/o;

    .line 156
    .line 157
    check-cast p2, Ljava/lang/Integer;

    .line 158
    .line 159
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    iget p1, p0, Lh2/r0;->h:I

    .line 163
    .line 164
    or-int/lit8 p1, p1, 0x1

    .line 165
    .line 166
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 167
    .line 168
    .line 169
    move-result v11

    .line 170
    iget-object v2, p0, Lh2/r0;->e:Lx2/s;

    .line 171
    .line 172
    iget-boolean v3, p0, Lh2/r0;->g:Z

    .line 173
    .line 174
    iget-object v8, p0, Lh2/r0;->f:Lk1/z0;

    .line 175
    .line 176
    iget v12, p0, Lh2/r0;->i:I

    .line 177
    .line 178
    invoke-static/range {v1 .. v12}, Lh2/r;->d(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lh2/q0;Le1/t;Lk1/z0;Lt2/b;Ll2/o;II)V

    .line 179
    .line 180
    .line 181
    goto :goto_0

    .line 182
    nop

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
