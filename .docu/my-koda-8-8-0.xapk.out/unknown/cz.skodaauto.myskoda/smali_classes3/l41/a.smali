.class public final synthetic Ll41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/c;

.field public final synthetic f:Ly31/g;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lz70/c;Ly31/g;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ll41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll41/a;->e:Lz70/c;

    iput-object p2, p0, Ll41/a;->f:Ly31/g;

    iput-object p3, p0, Ll41/a;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lz70/c;Ly31/g;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Ll41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll41/a;->e:Lz70/c;

    iput-object p2, p0, Ll41/a;->f:Ly31/g;

    iput-object p3, p0, Ll41/a;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ll41/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x41

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Ll41/a;->e:Lz70/c;

    .line 20
    .line 21
    iget-object v1, p0, Ll41/a;->f:Ly31/g;

    .line 22
    .line 23
    iget-object p0, p0, Ll41/a;->g:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, v1, p0, p1, p2}, Llp/xe;->d(Lz70/c;Ly31/g;Lay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    and-int/lit8 v0, p2, 0x3

    .line 36
    .line 37
    const/4 v1, 0x2

    .line 38
    const/4 v2, 0x1

    .line 39
    const/4 v3, 0x0

    .line 40
    if-eq v0, v1, :cond_0

    .line 41
    .line 42
    move v0, v2

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    move v0, v3

    .line 45
    :goto_0
    and-int/2addr p2, v2

    .line 46
    move-object v8, p1

    .line 47
    check-cast v8, Ll2/t;

    .line 48
    .line 49
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    if-eqz p1, :cond_4

    .line 54
    .line 55
    const/16 p1, 0x40

    .line 56
    .line 57
    iget-object p2, p0, Ll41/a;->e:Lz70/c;

    .line 58
    .line 59
    iget-object v0, p0, Ll41/a;->f:Ly31/g;

    .line 60
    .line 61
    iget-object p0, p0, Ll41/a;->g:Lay0/k;

    .line 62
    .line 63
    invoke-static {p2, v0, p0, v8, p1}, Llp/xe;->d(Lz70/c;Ly31/g;Lay0/k;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p2, Lz70/c;->a:Lij0/a;

    .line 67
    .line 68
    iget-boolean p2, v0, Ly31/g;->d:Z

    .line 69
    .line 70
    if-eqz p2, :cond_3

    .line 71
    .line 72
    const p2, 0x6830b2d9

    .line 73
    .line 74
    .line 75
    invoke-virtual {v8, p2}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    sget-object p2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 79
    .line 80
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 81
    .line 82
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Lj91/e;

    .line 87
    .line 88
    invoke-virtual {v0}, Lj91/e;->b()J

    .line 89
    .line 90
    .line 91
    move-result-wide v0

    .line 92
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 93
    .line 94
    invoke-static {p2, v0, v1, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    invoke-static {p2, v8, v3}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p2

    .line 105
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    if-nez p2, :cond_1

    .line 110
    .line 111
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 112
    .line 113
    if-ne v0, p2, :cond_2

    .line 114
    .line 115
    :cond_1
    new-instance v0, Lik/b;

    .line 116
    .line 117
    const/16 p2, 0x15

    .line 118
    .line 119
    invoke-direct {v0, p2, p0}, Lik/b;-><init>(ILay0/k;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_2
    move-object v4, v0

    .line 126
    check-cast v4, Lay0/a;

    .line 127
    .line 128
    new-array p0, v3, [Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p1, Ljj0/f;

    .line 131
    .line 132
    const p2, 0x7f12113e

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1, p2, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v5

    .line 139
    const p0, 0x7f12113c

    .line 140
    .line 141
    .line 142
    new-array p2, v3, [Ljava/lang/Object;

    .line 143
    .line 144
    invoke-virtual {p1, p0, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    const p0, 0x7f120382

    .line 149
    .line 150
    .line 151
    new-array p2, v3, [Ljava/lang/Object;

    .line 152
    .line 153
    invoke-virtual {p1, p0, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    const/4 v9, 0x0

    .line 158
    invoke-static/range {v4 .. v9}, Llp/xe;->b(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 159
    .line 160
    .line 161
    :goto_1
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_3
    const p0, 0x67ef3872

    .line 166
    .line 167
    .line 168
    invoke-virtual {v8, p0}, Ll2/t;->Y(I)V

    .line 169
    .line 170
    .line 171
    goto :goto_1

    .line 172
    :cond_4
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 173
    .line 174
    .line 175
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 176
    .line 177
    return-object p0

    .line 178
    nop

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
