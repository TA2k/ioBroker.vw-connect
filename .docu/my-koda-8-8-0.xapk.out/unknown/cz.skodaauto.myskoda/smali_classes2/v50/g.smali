.class public final synthetic Lv50/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Z


# direct methods
.method public synthetic constructor <init>(Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lv50/g;->d:Z

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lp1/p;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Integer;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Ll2/o;

    .line 10
    .line 11
    check-cast p4, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const-string p4, "$this$HorizontalPager"

    .line 17
    .line 18
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    sget-object p1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 22
    .line 23
    sget-object p4, Lk1/j;->c:Lk1/e;

    .line 24
    .line 25
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-static {p4, v0, p3, v1}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 29
    .line 30
    .line 31
    move-result-object p4

    .line 32
    move-object v0, p3

    .line 33
    check-cast v0, Ll2/t;

    .line 34
    .line 35
    iget-wide v2, v0, Ll2/t;->T:J

    .line 36
    .line 37
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-static {p3, p1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 55
    .line 56
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 57
    .line 58
    .line 59
    iget-boolean v5, v0, Ll2/t;->S:Z

    .line 60
    .line 61
    if-eqz v5, :cond_0

    .line 62
    .line 63
    invoke-virtual {v0, v4}, Ll2/t;->l(Lay0/a;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 68
    .line 69
    .line 70
    :goto_0
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 71
    .line 72
    invoke-static {v4, p4, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 73
    .line 74
    .line 75
    sget-object p4, Lv3/j;->f:Lv3/h;

    .line 76
    .line 77
    invoke-static {p4, v3, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 78
    .line 79
    .line 80
    sget-object p4, Lv3/j;->j:Lv3/h;

    .line 81
    .line 82
    iget-boolean v3, v0, Ll2/t;->S:Z

    .line 83
    .line 84
    if-nez v3, :cond_1

    .line 85
    .line 86
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v3

    .line 98
    if-nez v3, :cond_2

    .line 99
    .line 100
    :cond_1
    invoke-static {v2, v0, v2, p4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 101
    .line 102
    .line 103
    :cond_2
    sget-object p4, Lv3/j;->d:Lv3/h;

    .line 104
    .line 105
    invoke-static {p4, p1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 106
    .line 107
    .line 108
    iget-boolean p0, p0, Lv50/g;->d:Z

    .line 109
    .line 110
    const/4 p1, 0x6

    .line 111
    const/4 p4, 0x1

    .line 112
    if-eqz p2, :cond_5

    .line 113
    .line 114
    if-eq p2, p4, :cond_4

    .line 115
    .line 116
    const/4 v2, 0x2

    .line 117
    if-eq p2, v2, :cond_3

    .line 118
    .line 119
    const p0, -0x426bf18

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, p0}, Ll2/t;->Y(I)V

    .line 123
    .line 124
    .line 125
    :goto_1
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 126
    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_3
    const p2, 0x2928e1f4

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, p2}, Ll2/t;->Y(I)V

    .line 133
    .line 134
    .line 135
    invoke-static {p0, p3, p1}, Lv50/a;->m(ZLl2/o;I)V

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_4
    const p2, 0x2928dbb2

    .line 140
    .line 141
    .line 142
    invoke-virtual {v0, p2}, Ll2/t;->Y(I)V

    .line 143
    .line 144
    .line 145
    invoke-static {p0, p3, p1}, Lv50/a;->n(ZLl2/o;I)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_5
    const p2, 0x2928d572

    .line 153
    .line 154
    .line 155
    invoke-virtual {v0, p2}, Ll2/t;->Y(I)V

    .line 156
    .line 157
    .line 158
    invoke-static {p0, p3, p1}, Lv50/a;->l(ZLl2/o;I)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 162
    .line 163
    .line 164
    :goto_2
    invoke-virtual {v0, p4}, Ll2/t;->q(Z)V

    .line 165
    .line 166
    .line 167
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    return-object p0
.end method
