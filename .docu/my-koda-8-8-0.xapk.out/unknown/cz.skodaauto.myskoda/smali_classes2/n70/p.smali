.class public final synthetic Ln70/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:C

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(CZLjava/lang/String;I)V
    .locals 0

    .line 1
    const/4 p4, 0x1

    iput p4, p0, Ln70/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-char p1, p0, Ln70/p;->e:C

    iput-boolean p2, p0, Ln70/p;->f:Z

    iput-object p3, p0, Ln70/p;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Boolean;CZ)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ln70/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/p;->g:Ljava/lang/Object;

    iput-char p2, p0, Ln70/p;->e:C

    iput-boolean p3, p0, Ln70/p;->f:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ln70/p;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    iget-object v3, p0, Ln70/p;->g:Ljava/lang/Object;

    .line 7
    .line 8
    iget-boolean v4, p0, Ln70/p;->f:Z

    .line 9
    .line 10
    iget-char p0, p0, Ln70/p;->e:C

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast v3, Ljava/lang/String;

    .line 16
    .line 17
    check-cast p1, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    invoke-static {p0, v4, v3, p1, p2}, Ln70/r;->d(CZLjava/lang/String;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    return-object v1

    .line 32
    :pswitch_0
    check-cast v3, Ljava/lang/Boolean;

    .line 33
    .line 34
    check-cast p1, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    and-int/lit8 v0, p2, 0x3

    .line 43
    .line 44
    const/4 v5, 0x2

    .line 45
    const/4 v6, 0x0

    .line 46
    if-eq v0, v5, :cond_0

    .line 47
    .line 48
    move v0, v2

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move v0, v6

    .line 51
    :goto_0
    and-int/2addr p2, v2

    .line 52
    check-cast p1, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_7

    .line 59
    .line 60
    const/4 p2, 0x0

    .line 61
    if-nez v3, :cond_1

    .line 62
    .line 63
    const v0, 0x484bc6db

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 70
    .line 71
    .line 72
    move-object v0, p2

    .line 73
    goto :goto_4

    .line 74
    :cond_1
    const v0, 0x484bc6dc

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_3

    .line 85
    .line 86
    const v0, 0x297679d1

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    invoke-static {p1}, Ln70/a;->t0(Ll2/t;)Li91/b3;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    if-eqz v4, :cond_2

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_2
    move-object v0, p2

    .line 100
    :goto_1
    invoke-static {p2, p0, v0, p1, v6}, Ln70/a;->x(Lx2/s;CLi91/b3;Ll2/o;I)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 104
    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_3
    const v0, 0x29795938

    .line 108
    .line 109
    .line 110
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    invoke-static {p1}, Ln70/a;->t0(Ll2/t;)Li91/b3;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    if-eqz v4, :cond_4

    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_4
    move-object v0, p2

    .line 121
    :goto_2
    invoke-static {p2, p0, v0, p1, v6}, Ln70/a;->q0(Lx2/s;CLi91/b3;Ll2/o;I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 125
    .line 126
    .line 127
    :goto_3
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    move-object v0, v1

    .line 131
    :goto_4
    if-nez v0, :cond_6

    .line 132
    .line 133
    const v0, -0x5ecd825    # -1.91019E35f

    .line 134
    .line 135
    .line 136
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 137
    .line 138
    .line 139
    sget-object v0, Li91/l2;->d:Li91/l2;

    .line 140
    .line 141
    invoke-static {p1}, Ln70/a;->t0(Ll2/t;)Li91/b3;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    if-eqz v4, :cond_5

    .line 146
    .line 147
    goto :goto_5

    .line 148
    :cond_5
    move-object v0, p2

    .line 149
    :goto_5
    const/16 v2, 0x180

    .line 150
    .line 151
    invoke-static {p2, p0, v0, p1, v2}, Li91/j0;->d0(Lx2/s;CLi91/b3;Ll2/o;I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    goto :goto_6

    .line 158
    :cond_6
    const p0, -0x5ed0ae2

    .line 159
    .line 160
    .line 161
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 165
    .line 166
    .line 167
    goto :goto_6

    .line 168
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 169
    .line 170
    .line 171
    :goto_6
    return-object v1

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
