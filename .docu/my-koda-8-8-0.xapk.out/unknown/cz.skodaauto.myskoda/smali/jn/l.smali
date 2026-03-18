.class public final Ljn/l;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Ljava/util/List;

.field public final synthetic i:Lx2/s;

.field public final synthetic j:F

.field public final synthetic k:F

.field public final synthetic l:F


# direct methods
.method public constructor <init>(ILay0/k;Ljava/util/List;Lx2/s;FFF)V
    .locals 0

    .line 1
    iput p1, p0, Ljn/l;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Ljn/l;->g:Lay0/k;

    .line 4
    .line 5
    iput-object p3, p0, Ljn/l;->h:Ljava/util/List;

    .line 6
    .line 7
    iput-object p4, p0, Ljn/l;->i:Lx2/s;

    .line 8
    .line 9
    iput p5, p0, Ljn/l;->j:F

    .line 10
    .line 11
    iput p6, p0, Ljn/l;->k:F

    .line 12
    .line 13
    iput p7, p0, Ljn/l;->l:F

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Ll2/o;

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
    and-int/lit8 p2, p2, 0xb

    .line 10
    .line 11
    xor-int/lit8 p2, p2, 0x2

    .line 12
    .line 13
    if-nez p2, :cond_1

    .line 14
    .line 15
    move-object p2, p1

    .line 16
    check-cast p2, Ll2/t;

    .line 17
    .line 18
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 26
    .line 27
    .line 28
    goto/16 :goto_1

    .line 29
    .line 30
    :cond_1
    :goto_0
    check-cast p1, Ll2/t;

    .line 31
    .line 32
    const p2, 0x60bd4be5

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1, p2}, Ll2/t;->Z(I)V

    .line 36
    .line 37
    .line 38
    iget p2, p0, Ljn/l;->j:F

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    iget v1, p0, Ljn/l;->l:F

    .line 42
    .line 43
    iget v2, p0, Ljn/l;->k:F

    .line 44
    .line 45
    const v3, 0x3e99999a    # 0.3f

    .line 46
    .line 47
    .line 48
    iget-object v4, p0, Ljn/l;->i:Lx2/s;

    .line 49
    .line 50
    iget-object v5, p0, Ljn/l;->g:Lay0/k;

    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    iget-object v7, p0, Ljn/l;->h:Ljava/util/List;

    .line 54
    .line 55
    iget p0, p0, Ljn/l;->f:I

    .line 56
    .line 57
    const/4 v8, 0x1

    .line 58
    if-lez p0, :cond_2

    .line 59
    .line 60
    add-int/lit8 v9, p0, -0x1

    .line 61
    .line 62
    invoke-interface {v7, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    invoke-interface {v5, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v9

    .line 70
    check-cast v9, Ljava/lang/String;

    .line 71
    .line 72
    neg-float v10, p2

    .line 73
    invoke-static {v4, v0, v10, v8}, Landroidx/compose/foundation/layout/a;->k(Lx2/s;FFI)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v10

    .line 77
    div-float v11, v2, v1

    .line 78
    .line 79
    invoke-static {v3, v11}, Ljava/lang/Math;->max(FF)F

    .line 80
    .line 81
    .line 82
    move-result v11

    .line 83
    invoke-static {v10, v11}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v10

    .line 87
    invoke-static {v6, v9, p1, v10}, Llp/dc;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 88
    .line 89
    .line 90
    :cond_2
    invoke-virtual {p1, v6}, Ll2/t;->q(Z)V

    .line 91
    .line 92
    .line 93
    invoke-interface {v7, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v9

    .line 97
    invoke-interface {v5, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v9

    .line 101
    check-cast v9, Ljava/lang/String;

    .line 102
    .line 103
    int-to-float v10, v8

    .line 104
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 105
    .line 106
    .line 107
    move-result v11

    .line 108
    div-float/2addr v11, v1

    .line 109
    sub-float/2addr v10, v11

    .line 110
    invoke-static {v3, v10}, Ljava/lang/Math;->max(FF)F

    .line 111
    .line 112
    .line 113
    move-result v10

    .line 114
    invoke-static {v4, v10}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    invoke-static {v6, v9, p1, v10}, Llp/dc;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 119
    .line 120
    .line 121
    move-object v9, v7

    .line 122
    check-cast v9, Ljava/util/Collection;

    .line 123
    .line 124
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 125
    .line 126
    .line 127
    move-result v9

    .line 128
    sub-int/2addr v9, v8

    .line 129
    if-ge p0, v9, :cond_3

    .line 130
    .line 131
    add-int/2addr p0, v8

    .line 132
    invoke-interface {v7, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-interface {v5, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    check-cast p0, Ljava/lang/String;

    .line 141
    .line 142
    invoke-static {v4, v0, p2, v8}, Landroidx/compose/foundation/layout/a;->k(Lx2/s;FFI)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    neg-float v0, v2

    .line 147
    div-float/2addr v0, v1

    .line 148
    invoke-static {v3, v0}, Ljava/lang/Math;->max(FF)F

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    invoke-static {p2, v0}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 153
    .line 154
    .line 155
    move-result-object p2

    .line 156
    invoke-static {v6, p0, p1, p2}, Llp/dc;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 157
    .line 158
    .line 159
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    return-object p0
.end method
