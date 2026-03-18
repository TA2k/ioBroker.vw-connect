.class public final synthetic Ld00/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Ld00/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Ld00/r;->j:Ljava/lang/Object;

    iput-object p3, p0, Ld00/r;->f:Ljava/lang/Object;

    iput-object p4, p0, Ld00/r;->k:Ljava/lang/Object;

    iput-boolean p6, p0, Ld00/r;->e:Z

    iput-boolean p7, p0, Ld00/r;->g:Z

    iput-object p5, p0, Ld00/r;->h:Ljava/lang/Object;

    iput p1, p0, Ld00/r;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lc00/m1;ZZLx2/s;Lay0/a;Lay0/k;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ld00/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/r;->j:Ljava/lang/Object;

    iput-boolean p2, p0, Ld00/r;->e:Z

    iput-boolean p3, p0, Ld00/r;->g:Z

    iput-object p4, p0, Ld00/r;->f:Ljava/lang/Object;

    iput-object p5, p0, Ld00/r;->k:Ljava/lang/Object;

    iput-object p6, p0, Ld00/r;->h:Ljava/lang/Object;

    iput p7, p0, Ld00/r;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;ZLx2/s;ZLay0/k;Lay0/k;I)V
    .locals 1

    .line 3
    const/4 v0, 0x1

    iput v0, p0, Ld00/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/r;->j:Ljava/lang/Object;

    iput-boolean p2, p0, Ld00/r;->e:Z

    iput-object p3, p0, Ld00/r;->f:Ljava/lang/Object;

    iput-boolean p4, p0, Ld00/r;->g:Z

    iput-object p5, p0, Ld00/r;->h:Ljava/lang/Object;

    iput-object p6, p0, Ld00/r;->k:Ljava/lang/Object;

    iput p7, p0, Ld00/r;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ls71/k;Ls71/k;ZZLay0/k;I)V
    .locals 1

    .line 4
    const/4 v0, 0x3

    iput v0, p0, Ld00/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/r;->f:Ljava/lang/Object;

    iput-object p2, p0, Ld00/r;->j:Ljava/lang/Object;

    iput-object p3, p0, Ld00/r;->k:Ljava/lang/Object;

    iput-boolean p4, p0, Ld00/r;->e:Z

    iput-boolean p5, p0, Ld00/r;->g:Z

    iput-object p6, p0, Ld00/r;->h:Ljava/lang/Object;

    iput p7, p0, Ld00/r;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ld00/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld00/r;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lx2/s;

    .line 10
    .line 11
    iget-object v0, p0, Ld00/r;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ls71/k;

    .line 15
    .line 16
    iget-object v0, p0, Ld00/r;->k:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ls71/k;

    .line 20
    .line 21
    iget-object v0, p0, Ld00/r;->h:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v6, v0

    .line 24
    check-cast v6, Lay0/k;

    .line 25
    .line 26
    move-object v7, p1

    .line 27
    check-cast v7, Ll2/o;

    .line 28
    .line 29
    check-cast p2, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    iget p1, p0, Ld00/r;->i:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v8

    .line 42
    iget-boolean v4, p0, Ld00/r;->e:Z

    .line 43
    .line 44
    iget-boolean v5, p0, Ld00/r;->g:Z

    .line 45
    .line 46
    invoke-static/range {v1 .. v8}, Lz61/a;->j(Lx2/s;Ls71/k;Ls71/k;ZZLay0/k;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_0
    iget-object v0, p0, Ld00/r;->j:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v2, v0

    .line 55
    check-cast v2, Ljava/lang/String;

    .line 56
    .line 57
    iget-object v0, p0, Ld00/r;->f:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v3, v0

    .line 60
    check-cast v3, Ljava/lang/String;

    .line 61
    .line 62
    iget-object v0, p0, Ld00/r;->k:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v4, v0

    .line 65
    check-cast v4, Ljava/lang/String;

    .line 66
    .line 67
    iget-object v0, p0, Ld00/r;->h:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v5, v0

    .line 70
    check-cast v5, Ljava/lang/String;

    .line 71
    .line 72
    move-object v6, p1

    .line 73
    check-cast v6, Ll2/o;

    .line 74
    .line 75
    check-cast p2, Ljava/lang/Integer;

    .line 76
    .line 77
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    iget p1, p0, Ld00/r;->i:I

    .line 81
    .line 82
    or-int/lit8 p1, p1, 0x1

    .line 83
    .line 84
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    iget-boolean v7, p0, Ld00/r;->e:Z

    .line 89
    .line 90
    iget-boolean v8, p0, Ld00/r;->g:Z

    .line 91
    .line 92
    invoke-static/range {v1 .. v8}, Lrk/a;->c(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;ZZ)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :pswitch_1
    iget-object v0, p0, Ld00/r;->j:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v1, v0

    .line 99
    check-cast v1, Ljava/util/List;

    .line 100
    .line 101
    iget-object v0, p0, Ld00/r;->f:Ljava/lang/Object;

    .line 102
    .line 103
    move-object v3, v0

    .line 104
    check-cast v3, Lx2/s;

    .line 105
    .line 106
    iget-object v0, p0, Ld00/r;->h:Ljava/lang/Object;

    .line 107
    .line 108
    move-object v5, v0

    .line 109
    check-cast v5, Lay0/k;

    .line 110
    .line 111
    iget-object v0, p0, Ld00/r;->k:Ljava/lang/Object;

    .line 112
    .line 113
    move-object v6, v0

    .line 114
    check-cast v6, Lay0/k;

    .line 115
    .line 116
    move-object v7, p1

    .line 117
    check-cast v7, Ll2/o;

    .line 118
    .line 119
    check-cast p2, Ljava/lang/Integer;

    .line 120
    .line 121
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    iget p1, p0, Ld00/r;->i:I

    .line 125
    .line 126
    or-int/lit8 p1, p1, 0x1

    .line 127
    .line 128
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 129
    .line 130
    .line 131
    move-result v8

    .line 132
    iget-boolean v2, p0, Ld00/r;->e:Z

    .line 133
    .line 134
    iget-boolean v4, p0, Ld00/r;->g:Z

    .line 135
    .line 136
    invoke-static/range {v1 .. v8}, Llp/ya;->a(Ljava/util/List;ZLx2/s;ZLay0/k;Lay0/k;Ll2/o;I)V

    .line 137
    .line 138
    .line 139
    goto :goto_0

    .line 140
    :pswitch_2
    iget-object v0, p0, Ld00/r;->j:Ljava/lang/Object;

    .line 141
    .line 142
    move-object v1, v0

    .line 143
    check-cast v1, Lc00/m1;

    .line 144
    .line 145
    iget-object v0, p0, Ld00/r;->f:Ljava/lang/Object;

    .line 146
    .line 147
    move-object v4, v0

    .line 148
    check-cast v4, Lx2/s;

    .line 149
    .line 150
    iget-object v0, p0, Ld00/r;->k:Ljava/lang/Object;

    .line 151
    .line 152
    move-object v5, v0

    .line 153
    check-cast v5, Lay0/a;

    .line 154
    .line 155
    iget-object v0, p0, Ld00/r;->h:Ljava/lang/Object;

    .line 156
    .line 157
    move-object v6, v0

    .line 158
    check-cast v6, Lay0/k;

    .line 159
    .line 160
    move-object v7, p1

    .line 161
    check-cast v7, Ll2/o;

    .line 162
    .line 163
    check-cast p2, Ljava/lang/Integer;

    .line 164
    .line 165
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    iget p1, p0, Ld00/r;->i:I

    .line 169
    .line 170
    or-int/lit8 p1, p1, 0x1

    .line 171
    .line 172
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 173
    .line 174
    .line 175
    move-result v8

    .line 176
    iget-boolean v2, p0, Ld00/r;->e:Z

    .line 177
    .line 178
    iget-boolean v3, p0, Ld00/r;->g:Z

    .line 179
    .line 180
    invoke-static/range {v1 .. v8}, Ld00/o;->y(Lc00/m1;ZZLx2/s;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 181
    .line 182
    .line 183
    goto/16 :goto_0

    .line 184
    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
