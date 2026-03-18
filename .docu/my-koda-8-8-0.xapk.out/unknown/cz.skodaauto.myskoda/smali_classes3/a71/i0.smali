.class public final synthetic La71/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lx61/b;ZZZLt71/d;Ls71/h;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, La71/i0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/i0;->h:Ljava/lang/Object;

    iput-boolean p2, p0, La71/i0;->e:Z

    iput-boolean p3, p0, La71/i0;->f:Z

    iput-boolean p4, p0, La71/i0;->g:Z

    iput-object p5, p0, La71/i0;->i:Ljava/lang/Object;

    iput-object p6, p0, La71/i0;->j:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 2
    const/4 p7, 0x1

    iput p7, p0, La71/i0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, La71/i0;->e:Z

    iput-boolean p2, p0, La71/i0;->f:Z

    iput-boolean p3, p0, La71/i0;->g:Z

    iput-object p4, p0, La71/i0;->h:Ljava/lang/Object;

    iput-object p5, p0, La71/i0;->i:Ljava/lang/Object;

    iput-object p6, p0, La71/i0;->j:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, La71/i0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La71/i0;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v4, v0

    .line 9
    check-cast v4, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, La71/i0;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v5, v0

    .line 14
    check-cast v5, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, p0, La71/i0;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v6, v0

    .line 19
    check-cast v6, Ljava/lang/String;

    .line 20
    .line 21
    move-object v7, p1

    .line 22
    check-cast v7, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const p1, 0x36001

    .line 30
    .line 31
    .line 32
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 33
    .line 34
    .line 35
    move-result v8

    .line 36
    iget-boolean v1, p0, La71/i0;->e:Z

    .line 37
    .line 38
    iget-boolean v2, p0, La71/i0;->f:Z

    .line 39
    .line 40
    iget-boolean v3, p0, La71/i0;->g:Z

    .line 41
    .line 42
    invoke-static/range {v1 .. v8}, Llp/xe;->e(ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_0
    iget-object v0, p0, La71/i0;->h:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v0, Lx61/b;

    .line 51
    .line 52
    iget-object v1, p0, La71/i0;->i:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v1, Lt71/d;

    .line 55
    .line 56
    iget-object v2, p0, La71/i0;->j:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v2, Ls71/h;

    .line 59
    .line 60
    check-cast p1, Ll2/o;

    .line 61
    .line 62
    check-cast p2, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 65
    .line 66
    .line 67
    move-result p2

    .line 68
    and-int/lit8 v3, p2, 0x3

    .line 69
    .line 70
    const/4 v4, 0x2

    .line 71
    const/4 v5, 0x1

    .line 72
    const/4 v6, 0x0

    .line 73
    if-eq v3, v4, :cond_0

    .line 74
    .line 75
    move v3, v5

    .line 76
    goto :goto_0

    .line 77
    :cond_0
    move v3, v6

    .line 78
    :goto_0
    and-int/2addr p2, v5

    .line 79
    check-cast p1, Ll2/t;

    .line 80
    .line 81
    invoke-virtual {p1, p2, v3}, Ll2/t;->O(IZ)Z

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    if-eqz p2, :cond_4

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    if-eqz p2, :cond_2

    .line 92
    .line 93
    if-ne p2, v5, :cond_1

    .line 94
    .line 95
    const p0, 0x177938a3

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_1
    const p0, 0x6c1c685f

    .line 106
    .line 107
    .line 108
    invoke-static {p0, p1, v6}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    throw p0

    .line 113
    :cond_2
    const p2, 0x177189b6

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 117
    .line 118
    .line 119
    iget-boolean p2, p0, La71/i0;->e:Z

    .line 120
    .line 121
    if-eqz p2, :cond_3

    .line 122
    .line 123
    iget-boolean p2, p0, La71/i0;->f:Z

    .line 124
    .line 125
    if-nez p2, :cond_3

    .line 126
    .line 127
    const p2, 0x1772a79d

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 131
    .line 132
    .line 133
    iget-boolean p0, p0, La71/i0;->g:Z

    .line 134
    .line 135
    invoke-static {p0, v1, v2, p1, v6}, La71/s0;->b(ZLt71/d;Ls71/h;Ll2/o;I)V

    .line 136
    .line 137
    .line 138
    :goto_1
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_3
    const p0, 0x16cbc0e5

    .line 143
    .line 144
    .line 145
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :goto_2
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 154
    .line 155
    .line 156
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object p0

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
