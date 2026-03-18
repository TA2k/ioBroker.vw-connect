.class public final Li40/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lh40/m;

.field public final synthetic e:I

.field public final synthetic f:Lh40/q;

.field public final synthetic g:Lay0/k;


# direct methods
.method public constructor <init>(Lh40/m;ILh40/q;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li40/n;->d:Lh40/m;

    .line 5
    .line 6
    iput p2, p0, Li40/n;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Li40/n;->f:Lh40/q;

    .line 9
    .line 10
    iput-object p4, p0, Li40/n;->g:Lay0/k;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Lb1/a0;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    const-string p3, "$this$AnimatedVisibility"

    .line 11
    .line 12
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object p1, Lj91/a;->a:Ll2/u2;

    .line 16
    .line 17
    move-object v9, p2

    .line 18
    check-cast v9, Ll2/t;

    .line 19
    .line 20
    invoke-virtual {v9, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    check-cast p2, Lj91/c;

    .line 25
    .line 26
    iget p2, p2, Lj91/c;->c:F

    .line 27
    .line 28
    iget-object p3, p0, Li40/n;->f:Lh40/q;

    .line 29
    .line 30
    iget-object p3, p3, Lh40/q;->j:Ljava/util/List;

    .line 31
    .line 32
    invoke-static {p3}, Ljp/k1;->h(Ljava/util/List;)I

    .line 33
    .line 34
    .line 35
    move-result p3

    .line 36
    const/4 v0, 0x0

    .line 37
    iget v1, p0, Li40/n;->e:I

    .line 38
    .line 39
    if-ne v1, p3, :cond_0

    .line 40
    .line 41
    const p3, 0x2ea6372d

    .line 42
    .line 43
    .line 44
    invoke-virtual {v9, p3}, Ll2/t;->Y(I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v9, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p3

    .line 51
    check-cast p3, Lj91/c;

    .line 52
    .line 53
    iget p3, p3, Lj91/c;->d:F

    .line 54
    .line 55
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    const p3, 0x2ea78d44

    .line 60
    .line 61
    .line 62
    invoke-virtual {v9, p3}, Ll2/t;->Y(I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    int-to-float p3, v0

    .line 69
    :goto_0
    invoke-virtual {v9, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    check-cast v0, Lj91/c;

    .line 74
    .line 75
    iget v0, v0, Lj91/c;->k:F

    .line 76
    .line 77
    invoke-virtual {v9, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    check-cast p1, Lj91/c;

    .line 82
    .line 83
    iget p1, p1, Lj91/c;->k:F

    .line 84
    .line 85
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 86
    .line 87
    invoke-static {v1, v0, p2, p1, p3}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    iget-object p1, p0, Li40/n;->g:Lay0/k;

    .line 92
    .line 93
    invoke-virtual {v9, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    iget-object p3, p0, Li40/n;->d:Lh40/m;

    .line 98
    .line 99
    invoke-virtual {v9, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    or-int/2addr p2, v0

    .line 104
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    if-nez p2, :cond_1

    .line 109
    .line 110
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 111
    .line 112
    if-ne v0, p2, :cond_2

    .line 113
    .line 114
    :cond_1
    new-instance v0, Li40/m;

    .line 115
    .line 116
    const/4 p2, 0x0

    .line 117
    invoke-direct {v0, p1, p3, p2}, Li40/m;-><init>(Lay0/k;Lh40/m;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    :cond_2
    move-object v6, v0

    .line 124
    check-cast v6, Lay0/a;

    .line 125
    .line 126
    const/16 v7, 0xf

    .line 127
    .line 128
    const/4 v3, 0x0

    .line 129
    const/4 v4, 0x0

    .line 130
    const/4 v5, 0x0

    .line 131
    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    const/4 v10, 0x0

    .line 136
    const/16 v11, 0x1fc

    .line 137
    .line 138
    iget-object v0, p0, Li40/n;->d:Lh40/m;

    .line 139
    .line 140
    const/4 v2, 0x0

    .line 141
    const/4 v3, 0x0

    .line 142
    const/4 v6, 0x0

    .line 143
    const/4 v7, 0x0

    .line 144
    const/4 v8, 0x0

    .line 145
    invoke-static/range {v0 .. v11}, Li40/i;->c(Lh40/m;Lx2/s;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 146
    .line 147
    .line 148
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    return-object p0
.end method
