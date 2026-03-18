.class public final Lt3/b0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx2/s;


# direct methods
.method public synthetic constructor <init>(Lx2/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt3/b0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lt3/b0;->g:Lx2/s;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lt3/b0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/d2;

    .line 7
    .line 8
    iget-object p1, p1, Ll2/d2;->a:Ll2/o;

    .line 9
    .line 10
    check-cast p2, Ll2/o;

    .line 11
    .line 12
    check-cast p3, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    move-object p3, p2

    .line 21
    check-cast p3, Ll2/t;

    .line 22
    .line 23
    iget-wide v0, p3, Ll2/t;->T:J

    .line 24
    .line 25
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 26
    .line 27
    .line 28
    move-result p3

    .line 29
    invoke-static {p3}, Ljava/lang/Integer;->hashCode(I)I

    .line 30
    .line 31
    .line 32
    move-result p3

    .line 33
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 34
    .line 35
    iget-object p0, p0, Lt3/b0;->g:Lx2/s;

    .line 36
    .line 37
    if-ne p0, v0, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance v0, Landroidx/compose/ui/CompositionLocalMapInjectionElement;

    .line 41
    .line 42
    move-object v1, p2

    .line 43
    check-cast v1, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-direct {v0, v1}, Landroidx/compose/ui/CompositionLocalMapInjectionElement;-><init>(Ll2/p1;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v0, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p2, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    :goto_0
    check-cast p1, Ll2/t;

    .line 61
    .line 62
    const p2, 0x1e65194f

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, p2}, Ll2/t;->Z(I)V

    .line 66
    .line 67
    .line 68
    sget-object p2, Lv3/k;->m1:Lv3/j;

    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 74
    .line 75
    invoke-static {p2, p0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 76
    .line 77
    .line 78
    sget-object p0, Lv3/j;->j:Lv3/h;

    .line 79
    .line 80
    iget-boolean p2, p1, Ll2/t;->S:Z

    .line 81
    .line 82
    if-nez p2, :cond_1

    .line 83
    .line 84
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    if-nez p2, :cond_2

    .line 97
    .line 98
    :cond_1
    invoke-static {p3, p1, p3, p0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 99
    .line 100
    .line 101
    :cond_2
    const/4 p0, 0x0

    .line 102
    invoke-virtual {p1, p0}, Ll2/t;->q(Z)V

    .line 103
    .line 104
    .line 105
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    return-object p0

    .line 108
    :pswitch_0
    check-cast p1, Ll2/d2;

    .line 109
    .line 110
    iget-object p1, p1, Ll2/d2;->a:Ll2/o;

    .line 111
    .line 112
    check-cast p2, Ll2/o;

    .line 113
    .line 114
    check-cast p3, Ljava/lang/Number;

    .line 115
    .line 116
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 117
    .line 118
    .line 119
    move-object p3, p2

    .line 120
    check-cast p3, Ll2/t;

    .line 121
    .line 122
    iget-wide v0, p3, Ll2/t;->T:J

    .line 123
    .line 124
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 125
    .line 126
    .line 127
    move-result p3

    .line 128
    iget-object p0, p0, Lt3/b0;->g:Lx2/s;

    .line 129
    .line 130
    invoke-static {p2, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    check-cast p1, Ll2/t;

    .line 135
    .line 136
    const p2, 0x1e65194f

    .line 137
    .line 138
    .line 139
    invoke-virtual {p1, p2}, Ll2/t;->Z(I)V

    .line 140
    .line 141
    .line 142
    sget-object p2, Lv3/k;->m1:Lv3/j;

    .line 143
    .line 144
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 148
    .line 149
    invoke-static {p2, p0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    sget-object p0, Lv3/j;->j:Lv3/h;

    .line 153
    .line 154
    iget-boolean p2, p1, Ll2/t;->S:Z

    .line 155
    .line 156
    if-nez p2, :cond_3

    .line 157
    .line 158
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p2

    .line 162
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result p2

    .line 170
    if-nez p2, :cond_4

    .line 171
    .line 172
    :cond_3
    invoke-static {p3, p1, p3, p0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 173
    .line 174
    .line 175
    :cond_4
    const/4 p0, 0x0

    .line 176
    invoke-virtual {p1, p0}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    return-object p0

    .line 182
    nop

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
