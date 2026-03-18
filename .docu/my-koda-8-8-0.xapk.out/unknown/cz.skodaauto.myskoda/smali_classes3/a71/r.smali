.class public final synthetic La71/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Lay0/a;Z)V
    .locals 0

    .line 1
    iput p1, p0, La71/r;->d:I

    .line 2
    .line 3
    iput-boolean p4, p0, La71/r;->e:Z

    .line 4
    .line 5
    iput-object p2, p0, La71/r;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, La71/r;->g:Lay0/a;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, La71/r;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/q;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$DriveControlGridRow"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    move-object v7, p2

    .line 33
    check-cast v7, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v7, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    sget-object p1, Lh71/o;->a:Ll2/u2;

    .line 42
    .line 43
    invoke-virtual {v7, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lh71/n;

    .line 48
    .line 49
    iget p1, p1, Lh71/n;->i:F

    .line 50
    .line 51
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 52
    .line 53
    invoke-static {p2, p1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    const/high16 p2, 0x3f800000    # 1.0f

    .line 58
    .line 59
    invoke-static {p1, p2, v1}, Landroidx/compose/foundation/layout/a;->d(Lx2/s;FZ)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    sget-object p1, Lh71/q;->a:Ll2/e0;

    .line 64
    .line 65
    invoke-virtual {v7, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    check-cast p1, Lh71/p;

    .line 70
    .line 71
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    const v3, 0x7f0805c1

    .line 75
    .line 76
    .line 77
    const/4 v8, 0x0

    .line 78
    iget-boolean v4, p0, La71/r;->e:Z

    .line 79
    .line 80
    iget-object v5, p0, La71/r;->f:Lay0/a;

    .line 81
    .line 82
    iget-object v6, p0, La71/r;->g:Lay0/a;

    .line 83
    .line 84
    invoke-static/range {v2 .. v8}, Lkp/r7;->a(Lx2/s;IZLay0/a;Lay0/a;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_0
    const-string v0, "$this$DriveControlGridRow"

    .line 95
    .line 96
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    and-int/lit8 p1, p3, 0x11

    .line 100
    .line 101
    const/16 v0, 0x10

    .line 102
    .line 103
    const/4 v1, 0x1

    .line 104
    if-eq p1, v0, :cond_2

    .line 105
    .line 106
    move p1, v1

    .line 107
    goto :goto_2

    .line 108
    :cond_2
    const/4 p1, 0x0

    .line 109
    :goto_2
    and-int/2addr p3, v1

    .line 110
    move-object v7, p2

    .line 111
    check-cast v7, Ll2/t;

    .line 112
    .line 113
    invoke-virtual {v7, p3, p1}, Ll2/t;->O(IZ)Z

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-eqz p1, :cond_3

    .line 118
    .line 119
    sget-object p1, Lh71/o;->a:Ll2/u2;

    .line 120
    .line 121
    invoke-virtual {v7, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    check-cast p1, Lh71/n;

    .line 126
    .line 127
    iget p1, p1, Lh71/n;->i:F

    .line 128
    .line 129
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 130
    .line 131
    invoke-static {p2, p1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    const/high16 p2, 0x3f800000    # 1.0f

    .line 136
    .line 137
    invoke-static {p1, p2, v1}, Landroidx/compose/foundation/layout/a;->d(Lx2/s;FZ)Lx2/s;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    sget-object p1, Lh71/q;->a:Ll2/e0;

    .line 142
    .line 143
    invoke-virtual {v7, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    check-cast p1, Lh71/p;

    .line 148
    .line 149
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    const v3, 0x7f0805b7

    .line 153
    .line 154
    .line 155
    const/4 v8, 0x0

    .line 156
    iget-boolean v4, p0, La71/r;->e:Z

    .line 157
    .line 158
    iget-object v5, p0, La71/r;->f:Lay0/a;

    .line 159
    .line 160
    iget-object v6, p0, La71/r;->g:Lay0/a;

    .line 161
    .line 162
    invoke-static/range {v2 .. v8}, Lkp/r7;->a(Lx2/s;IZLay0/a;Lay0/a;Ll2/o;I)V

    .line 163
    .line 164
    .line 165
    goto :goto_3

    .line 166
    :cond_3
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 167
    .line 168
    .line 169
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    return-object p0

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
