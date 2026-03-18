.class public final synthetic Ldl/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Integer;Li91/h1;Lx2/s;Lay0/a;ZLe1/t;ZLjava/lang/String;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Ldl/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldl/f;->i:Ljava/lang/Object;

    iput-object p2, p0, Ldl/f;->j:Ljava/lang/Object;

    iput-object p3, p0, Ldl/f;->k:Ljava/lang/Object;

    iput-object p4, p0, Ldl/f;->e:Lay0/a;

    iput-boolean p5, p0, Ldl/f;->f:Z

    iput-object p6, p0, Ldl/f;->l:Ljava/lang/Object;

    iput-boolean p7, p0, Ldl/f;->g:Z

    iput-object p8, p0, Ldl/f;->h:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;ZZLjava/lang/String;I)V
    .locals 0

    .line 2
    const/4 p9, 0x0

    iput p9, p0, Ldl/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldl/f;->h:Ljava/lang/String;

    iput-object p2, p0, Ldl/f;->i:Ljava/lang/Object;

    iput-object p3, p0, Ldl/f;->j:Ljava/lang/Object;

    iput-object p4, p0, Ldl/f;->l:Ljava/lang/Object;

    iput-object p5, p0, Ldl/f;->e:Lay0/a;

    iput-boolean p6, p0, Ldl/f;->f:Z

    iput-boolean p7, p0, Ldl/f;->g:Z

    iput-object p8, p0, Ldl/f;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Ldl/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ldl/f;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v10, v0

    .line 9
    check-cast v10, Ljava/lang/Integer;

    .line 10
    .line 11
    iget-object v0, p0, Ldl/f;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Li91/h1;

    .line 15
    .line 16
    iget-object v0, p0, Ldl/f;->k:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Lx2/s;

    .line 20
    .line 21
    iget-object v0, p0, Ldl/f;->l:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v6, v0

    .line 24
    check-cast v6, Le1/t;

    .line 25
    .line 26
    check-cast p1, Ll2/o;

    .line 27
    .line 28
    check-cast p2, Ljava/lang/Integer;

    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    and-int/lit8 v0, p2, 0x3

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x1

    .line 39
    if-eq v0, v1, :cond_0

    .line 40
    .line 41
    move v0, v5

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    move v0, v4

    .line 44
    :goto_0
    and-int/2addr p2, v5

    .line 45
    check-cast p1, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_2

    .line 52
    .line 53
    const/4 p2, 0x6

    .line 54
    const/16 v0, 0x10

    .line 55
    .line 56
    if-eqz v10, :cond_1

    .line 57
    .line 58
    const/16 v1, 0xc

    .line 59
    .line 60
    int-to-float v1, v1

    .line 61
    int-to-float v0, v0

    .line 62
    int-to-float p2, p2

    .line 63
    new-instance v5, Lk1/a1;

    .line 64
    .line 65
    invoke-direct {v5, v1, p2, v0, p2}, Lk1/a1;-><init>(FFFF)V

    .line 66
    .line 67
    .line 68
    :goto_1
    move-object v7, v5

    .line 69
    goto :goto_2

    .line 70
    :cond_1
    int-to-float v0, v0

    .line 71
    int-to-float p2, p2

    .line 72
    new-instance v5, Lk1/a1;

    .line 73
    .line 74
    invoke-direct {v5, v0, p2, v0, p2}, Lk1/a1;-><init>(FFFF)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :goto_2
    sget-object p2, Lh2/k5;->c:Ll2/u2;

    .line 79
    .line 80
    int-to-float v0, v4

    .line 81
    new-instance v1, Lt4/f;

    .line 82
    .line 83
    invoke-direct {v1, v0}, Lt4/f;-><init>(F)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2, v1}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    new-instance v1, La71/x;

    .line 91
    .line 92
    iget-object v4, p0, Ldl/f;->e:Lay0/a;

    .line 93
    .line 94
    iget-boolean v5, p0, Ldl/f;->f:Z

    .line 95
    .line 96
    iget-boolean v8, p0, Ldl/f;->g:Z

    .line 97
    .line 98
    iget-object v9, p0, Ldl/f;->h:Ljava/lang/String;

    .line 99
    .line 100
    invoke-direct/range {v1 .. v10}, La71/x;-><init>(Li91/h1;Lx2/s;Lay0/a;ZLe1/t;Lk1/a1;ZLjava/lang/String;Ljava/lang/Integer;)V

    .line 101
    .line 102
    .line 103
    const p0, 0x4cc96b0c    # 1.0560112E8f

    .line 104
    .line 105
    .line 106
    invoke-static {p0, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    const/16 v0, 0x38

    .line 111
    .line 112
    invoke-static {p2, p0, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 113
    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 117
    .line 118
    .line 119
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_0
    iget-object v0, p0, Ldl/f;->i:Ljava/lang/Object;

    .line 123
    .line 124
    move-object v2, v0

    .line 125
    check-cast v2, Ljava/lang/String;

    .line 126
    .line 127
    iget-object v0, p0, Ldl/f;->j:Ljava/lang/Object;

    .line 128
    .line 129
    move-object v3, v0

    .line 130
    check-cast v3, Ljava/lang/String;

    .line 131
    .line 132
    iget-object v0, p0, Ldl/f;->l:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v4, v0

    .line 135
    check-cast v4, Lay0/k;

    .line 136
    .line 137
    iget-object v0, p0, Ldl/f;->k:Ljava/lang/Object;

    .line 138
    .line 139
    move-object v8, v0

    .line 140
    check-cast v8, Ljava/lang/String;

    .line 141
    .line 142
    move-object v9, p1

    .line 143
    check-cast v9, Ll2/o;

    .line 144
    .line 145
    check-cast p2, Ljava/lang/Integer;

    .line 146
    .line 147
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    const/4 p1, 0x1

    .line 151
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    iget-object v1, p0, Ldl/f;->h:Ljava/lang/String;

    .line 156
    .line 157
    iget-object v5, p0, Ldl/f;->e:Lay0/a;

    .line 158
    .line 159
    iget-boolean v6, p0, Ldl/f;->f:Z

    .line 160
    .line 161
    iget-boolean v7, p0, Ldl/f;->g:Z

    .line 162
    .line 163
    invoke-static/range {v1 .. v10}, Ldl/a;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;ZZLjava/lang/String;Ll2/o;I)V

    .line 164
    .line 165
    .line 166
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    return-object p0

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
