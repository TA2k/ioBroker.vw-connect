.class public final synthetic Ln70/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/k0;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lm70/k0;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ln70/z;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/z;->e:Lm70/k0;

    iput-object p2, p0, Ln70/z;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lm70/k0;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p3, 0x1

    iput p3, p0, Ln70/z;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/z;->e:Lm70/k0;

    iput-object p2, p0, Ln70/z;->f:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln70/z;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v3, v0, Ln70/z;->e:Lm70/k0;

    .line 25
    .line 26
    iget-object v0, v0, Ln70/z;->f:Lay0/k;

    .line 27
    .line 28
    invoke-static {v3, v0, v1, v2}, Ln70/a;->U(Lm70/k0;Lay0/k;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_0
    move-object/from16 v1, p1

    .line 35
    .line 36
    check-cast v1, Ll2/o;

    .line 37
    .line 38
    move-object/from16 v2, p2

    .line 39
    .line 40
    check-cast v2, Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    and-int/lit8 v3, v2, 0x3

    .line 47
    .line 48
    const/4 v4, 0x2

    .line 49
    const/4 v5, 0x1

    .line 50
    if-eq v3, v4, :cond_0

    .line 51
    .line 52
    move v3, v5

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 v3, 0x0

    .line 55
    :goto_0
    and-int/2addr v2, v5

    .line 56
    move-object v14, v1

    .line 57
    check-cast v14, Ll2/t;

    .line 58
    .line 59
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_3

    .line 64
    .line 65
    const v1, 0x7f121475

    .line 66
    .line 67
    .line 68
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    iget-object v1, v0, Ln70/z;->e:Lm70/k0;

    .line 73
    .line 74
    iget-object v6, v1, Lm70/k0;->p:Ljava/lang/String;

    .line 75
    .line 76
    new-instance v8, Li91/z1;

    .line 77
    .line 78
    new-instance v2, Lg4/g;

    .line 79
    .line 80
    iget-object v1, v1, Lm70/k0;->o:Ljava/lang/String;

    .line 81
    .line 82
    invoke-direct {v2, v1}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const v1, 0x7f08033b

    .line 86
    .line 87
    .line 88
    invoke-direct {v8, v2, v1}, Li91/z1;-><init>(Lg4/g;I)V

    .line 89
    .line 90
    .line 91
    iget-object v0, v0, Ln70/z;->f:Lay0/k;

    .line 92
    .line 93
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    if-nez v1, :cond_1

    .line 102
    .line 103
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 104
    .line 105
    if-ne v2, v1, :cond_2

    .line 106
    .line 107
    :cond_1
    new-instance v2, Llk/f;

    .line 108
    .line 109
    const/16 v1, 0x19

    .line 110
    .line 111
    invoke-direct {v2, v1, v0}, Llk/f;-><init>(ILay0/k;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :cond_2
    move-object v11, v2

    .line 118
    check-cast v11, Lay0/a;

    .line 119
    .line 120
    const/16 v16, 0x30

    .line 121
    .line 122
    const/16 v17, 0x76a

    .line 123
    .line 124
    const/4 v5, 0x0

    .line 125
    const/4 v7, 0x0

    .line 126
    const/4 v9, 0x0

    .line 127
    const/4 v10, 0x0

    .line 128
    const/4 v12, 0x0

    .line 129
    const-string v13, "trip_detail_price_electric"

    .line 130
    .line 131
    const/4 v15, 0x0

    .line 132
    invoke-static/range {v4 .. v17}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 133
    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 137
    .line 138
    .line 139
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object v0

    .line 142
    nop

    .line 143
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
