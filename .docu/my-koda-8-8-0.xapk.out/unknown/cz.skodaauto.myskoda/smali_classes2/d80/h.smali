.class public final synthetic Ld80/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lc80/r;Lx2/s;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/k;III)V
    .locals 0

    .line 1
    iput p11, p0, Ld80/h;->d:I

    iput-object p1, p0, Ld80/h;->e:Ljava/lang/Object;

    iput-object p2, p0, Ld80/h;->f:Ljava/lang/Object;

    iput-object p3, p0, Ld80/h;->g:Lay0/a;

    iput-object p4, p0, Ld80/h;->h:Lay0/k;

    iput-object p5, p0, Ld80/h;->i:Lay0/a;

    iput-object p6, p0, Ld80/h;->j:Ljava/lang/Object;

    iput-object p7, p0, Ld80/h;->k:Ljava/lang/Object;

    iput-object p8, p0, Ld80/h;->l:Ljava/lang/Object;

    iput p9, p0, Ld80/h;->m:I

    iput p10, p0, Ld80/h;->n:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;Lay0/a;II)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Ld80/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld80/h;->e:Ljava/lang/Object;

    iput-object p2, p0, Ld80/h;->f:Ljava/lang/Object;

    iput-object p3, p0, Ld80/h;->j:Ljava/lang/Object;

    iput-object p4, p0, Ld80/h;->k:Ljava/lang/Object;

    iput-object p5, p0, Ld80/h;->l:Ljava/lang/Object;

    iput-object p6, p0, Ld80/h;->h:Lay0/k;

    iput-object p7, p0, Ld80/h;->g:Lay0/a;

    iput-object p8, p0, Ld80/h;->i:Lay0/a;

    iput p9, p0, Ld80/h;->m:I

    iput p10, p0, Ld80/h;->n:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Ld80/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld80/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Ld80/h;->f:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, p0, Ld80/h;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v0, p0, Ld80/h;->k:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v4, v0

    .line 24
    check-cast v4, Ljava/lang/String;

    .line 25
    .line 26
    iget-object v0, p0, Ld80/h;->l:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v5, v0

    .line 29
    check-cast v5, Ljava/lang/String;

    .line 30
    .line 31
    move-object v9, p1

    .line 32
    check-cast v9, Ll2/o;

    .line 33
    .line 34
    check-cast p2, Ljava/lang/Integer;

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    iget p1, p0, Ld80/h;->m:I

    .line 40
    .line 41
    or-int/lit8 p1, p1, 0x1

    .line 42
    .line 43
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 44
    .line 45
    .line 46
    move-result v10

    .line 47
    iget-object v6, p0, Ld80/h;->h:Lay0/k;

    .line 48
    .line 49
    iget-object v7, p0, Ld80/h;->g:Lay0/a;

    .line 50
    .line 51
    iget-object v8, p0, Ld80/h;->i:Lay0/a;

    .line 52
    .line 53
    iget v11, p0, Ld80/h;->n:I

    .line 54
    .line 55
    invoke-static/range {v1 .. v11}, Laj0/a;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 56
    .line 57
    .line 58
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_0
    iget-object v0, p0, Ld80/h;->e:Ljava/lang/Object;

    .line 62
    .line 63
    move-object v1, v0

    .line 64
    check-cast v1, Lc80/r;

    .line 65
    .line 66
    iget-object v0, p0, Ld80/h;->f:Ljava/lang/Object;

    .line 67
    .line 68
    move-object v2, v0

    .line 69
    check-cast v2, Lx2/s;

    .line 70
    .line 71
    iget-object v0, p0, Ld80/h;->j:Ljava/lang/Object;

    .line 72
    .line 73
    move-object v6, v0

    .line 74
    check-cast v6, Lay0/a;

    .line 75
    .line 76
    iget-object v0, p0, Ld80/h;->k:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v7, v0

    .line 79
    check-cast v7, Lay0/a;

    .line 80
    .line 81
    iget-object v0, p0, Ld80/h;->l:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v8, v0

    .line 84
    check-cast v8, Lay0/k;

    .line 85
    .line 86
    move-object v9, p1

    .line 87
    check-cast v9, Ll2/o;

    .line 88
    .line 89
    check-cast p2, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    iget p1, p0, Ld80/h;->m:I

    .line 95
    .line 96
    or-int/lit8 p1, p1, 0x1

    .line 97
    .line 98
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result v10

    .line 102
    iget-object v3, p0, Ld80/h;->g:Lay0/a;

    .line 103
    .line 104
    iget-object v4, p0, Ld80/h;->h:Lay0/k;

    .line 105
    .line 106
    iget-object v5, p0, Ld80/h;->i:Lay0/a;

    .line 107
    .line 108
    iget v11, p0, Ld80/h;->n:I

    .line 109
    .line 110
    invoke-static/range {v1 .. v11}, Ld80/b;->w(Lc80/r;Lx2/s;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Ll2/o;II)V

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :pswitch_1
    iget-object v0, p0, Ld80/h;->e:Ljava/lang/Object;

    .line 115
    .line 116
    move-object v1, v0

    .line 117
    check-cast v1, Lc80/r;

    .line 118
    .line 119
    iget-object v0, p0, Ld80/h;->f:Ljava/lang/Object;

    .line 120
    .line 121
    move-object v2, v0

    .line 122
    check-cast v2, Lx2/s;

    .line 123
    .line 124
    iget-object v0, p0, Ld80/h;->j:Ljava/lang/Object;

    .line 125
    .line 126
    move-object v6, v0

    .line 127
    check-cast v6, Lay0/a;

    .line 128
    .line 129
    iget-object v0, p0, Ld80/h;->k:Ljava/lang/Object;

    .line 130
    .line 131
    move-object v7, v0

    .line 132
    check-cast v7, Lay0/a;

    .line 133
    .line 134
    iget-object v0, p0, Ld80/h;->l:Ljava/lang/Object;

    .line 135
    .line 136
    move-object v8, v0

    .line 137
    check-cast v8, Lay0/k;

    .line 138
    .line 139
    move-object v9, p1

    .line 140
    check-cast v9, Ll2/o;

    .line 141
    .line 142
    check-cast p2, Ljava/lang/Integer;

    .line 143
    .line 144
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    iget p1, p0, Ld80/h;->m:I

    .line 148
    .line 149
    or-int/lit8 p1, p1, 0x1

    .line 150
    .line 151
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    iget-object v3, p0, Ld80/h;->g:Lay0/a;

    .line 156
    .line 157
    iget-object v4, p0, Ld80/h;->h:Lay0/k;

    .line 158
    .line 159
    iget-object v5, p0, Ld80/h;->i:Lay0/a;

    .line 160
    .line 161
    iget v11, p0, Ld80/h;->n:I

    .line 162
    .line 163
    invoke-static/range {v1 .. v11}, Ld80/b;->w(Lc80/r;Lx2/s;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Ll2/o;II)V

    .line 164
    .line 165
    .line 166
    goto :goto_0

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
