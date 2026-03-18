.class public final Lz20/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lh2/r8;

.field public final synthetic j:Lvy0/b0;


# direct methods
.method public constructor <init>(Ljava/util/List;Lx2/s;Lay0/k;Lay0/k;Lay0/k;Lh2/r8;Lvy0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz20/n;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Lz20/n;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Lz20/n;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Lz20/n;->g:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Lz20/n;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lz20/n;->i:Lh2/r8;

    .line 15
    .line 16
    iput-object p7, p0, Lz20/n;->j:Lvy0/b0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Ll2/o;

    .line 10
    .line 11
    check-cast p4, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p4

    .line 17
    and-int/lit8 v0, p4, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    move-object v0, p3

    .line 22
    check-cast v0, Ll2/t;

    .line 23
    .line 24
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    const/4 p1, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p1, 0x2

    .line 33
    :goto_0
    or-int/2addr p1, p4

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move p1, p4

    .line 36
    :goto_1
    and-int/lit8 p4, p4, 0x30

    .line 37
    .line 38
    if-nez p4, :cond_3

    .line 39
    .line 40
    move-object p4, p3

    .line 41
    check-cast p4, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 44
    .line 45
    .line 46
    move-result p4

    .line 47
    if-eqz p4, :cond_2

    .line 48
    .line 49
    const/16 p4, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 p4, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr p1, p4

    .line 55
    :cond_3
    and-int/lit16 p4, p1, 0x93

    .line 56
    .line 57
    const/16 v0, 0x92

    .line 58
    .line 59
    const/4 v1, 0x0

    .line 60
    const/4 v2, 0x1

    .line 61
    if-eq p4, v0, :cond_4

    .line 62
    .line 63
    move p4, v2

    .line 64
    goto :goto_3

    .line 65
    :cond_4
    move p4, v1

    .line 66
    :goto_3
    and-int/2addr p1, v2

    .line 67
    move-object v9, p3

    .line 68
    check-cast v9, Ll2/t;

    .line 69
    .line 70
    invoke-virtual {v9, p1, p4}, Ll2/t;->O(IZ)Z

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    if-eqz p1, :cond_9

    .line 75
    .line 76
    iget-object p1, p0, Lz20/n;->d:Ljava/util/List;

    .line 77
    .line 78
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    move-object v2, p1

    .line 83
    check-cast v2, Ly20/g;

    .line 84
    .line 85
    const p1, -0x49c7da8b

    .line 86
    .line 87
    .line 88
    invoke-virtual {v9, p1}, Ll2/t;->Y(I)V

    .line 89
    .line 90
    .line 91
    iget-object p1, p0, Lz20/n;->f:Lay0/k;

    .line 92
    .line 93
    invoke-virtual {v9, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p3

    .line 101
    or-int/2addr p2, p3

    .line 102
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p3

    .line 106
    sget-object p4, Ll2/n;->a:Ll2/x0;

    .line 107
    .line 108
    if-nez p2, :cond_5

    .line 109
    .line 110
    if-ne p3, p4, :cond_6

    .line 111
    .line 112
    :cond_5
    new-instance p3, Lz20/c;

    .line 113
    .line 114
    const/4 p2, 0x1

    .line 115
    invoke-direct {p3, p1, v2, p2}, Lz20/c;-><init>(Lay0/k;Ly20/g;I)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v9, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_6
    move-object v4, p3

    .line 122
    check-cast v4, Lay0/a;

    .line 123
    .line 124
    iget-object p1, p0, Lz20/n;->g:Lay0/k;

    .line 125
    .line 126
    invoke-virtual {v9, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p2

    .line 130
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result p3

    .line 134
    or-int/2addr p2, p3

    .line 135
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p3

    .line 139
    if-nez p2, :cond_7

    .line 140
    .line 141
    if-ne p3, p4, :cond_8

    .line 142
    .line 143
    :cond_7
    new-instance p3, Lz20/c;

    .line 144
    .line 145
    const/4 p2, 0x2

    .line 146
    invoke-direct {p3, p1, v2, p2}, Lz20/c;-><init>(Lay0/k;Ly20/g;I)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v9, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    :cond_8
    move-object v5, p3

    .line 153
    check-cast v5, Lay0/a;

    .line 154
    .line 155
    iget-object v8, p0, Lz20/n;->j:Lvy0/b0;

    .line 156
    .line 157
    const/16 v10, 0x30

    .line 158
    .line 159
    iget-object v3, p0, Lz20/n;->e:Lx2/s;

    .line 160
    .line 161
    iget-object v6, p0, Lz20/n;->h:Lay0/k;

    .line 162
    .line 163
    iget-object v7, p0, Lz20/n;->i:Lh2/r8;

    .line 164
    .line 165
    invoke-static/range {v2 .. v10}, Lz20/a;->i(Ly20/g;Lx2/s;Lay0/a;Lay0/a;Lay0/k;Lh2/r8;Lvy0/b0;Ll2/o;I)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v9, v1}, Ll2/t;->q(Z)V

    .line 169
    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_9
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 173
    .line 174
    .line 175
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 176
    .line 177
    return-object p0
.end method
