.class public final synthetic Lh70/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lg61/q;

.field public final synthetic f:Lg61/p;

.field public final synthetic g:Z

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lvy0/b0;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/k;

.field public final synthetic p:Lay0/a;

.field public final synthetic q:Lay0/k;

.field public final synthetic r:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lg61/p;Lg61/q;Lvy0/b0;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh70/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p12, p0, Lh70/h;->e:Lg61/q;

    iput-object p11, p0, Lh70/h;->f:Lg61/p;

    iput-boolean p14, p0, Lh70/h;->g:Z

    iput-object p8, p0, Lh70/h;->h:Lay0/k;

    iput-object p1, p0, Lh70/h;->i:Lay0/a;

    iput-object p13, p0, Lh70/h;->j:Lvy0/b0;

    iput-object p2, p0, Lh70/h;->k:Lay0/a;

    iput-object p3, p0, Lh70/h;->l:Lay0/a;

    iput-object p4, p0, Lh70/h;->m:Lay0/a;

    iput-object p5, p0, Lh70/h;->n:Lay0/a;

    iput-object p9, p0, Lh70/h;->o:Lay0/k;

    iput-object p6, p0, Lh70/h;->p:Lay0/a;

    iput-object p10, p0, Lh70/h;->q:Lay0/k;

    iput-object p7, p0, Lh70/h;->r:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lg61/q;Lg61/p;ZLay0/k;Lay0/a;Lvy0/b0;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lh70/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh70/h;->e:Lg61/q;

    iput-object p2, p0, Lh70/h;->f:Lg61/p;

    iput-boolean p3, p0, Lh70/h;->g:Z

    iput-object p4, p0, Lh70/h;->h:Lay0/k;

    iput-object p5, p0, Lh70/h;->i:Lay0/a;

    iput-object p6, p0, Lh70/h;->j:Lvy0/b0;

    iput-object p7, p0, Lh70/h;->k:Lay0/a;

    iput-object p8, p0, Lh70/h;->l:Lay0/a;

    iput-object p9, p0, Lh70/h;->m:Lay0/a;

    iput-object p10, p0, Lh70/h;->n:Lay0/a;

    iput-object p11, p0, Lh70/h;->o:Lay0/k;

    iput-object p12, p0, Lh70/h;->p:Lay0/a;

    iput-object p13, p0, Lh70/h;->q:Lay0/k;

    iput-object p14, p0, Lh70/h;->r:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh70/h;->d:I

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
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    check-cast v1, Ll2/t;

    .line 31
    .line 32
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    const/16 v19, 0x0

    .line 39
    .line 40
    iget-object v4, v0, Lh70/h;->e:Lg61/q;

    .line 41
    .line 42
    iget-object v5, v0, Lh70/h;->f:Lg61/p;

    .line 43
    .line 44
    iget-boolean v6, v0, Lh70/h;->g:Z

    .line 45
    .line 46
    iget-object v7, v0, Lh70/h;->h:Lay0/k;

    .line 47
    .line 48
    iget-object v8, v0, Lh70/h;->i:Lay0/a;

    .line 49
    .line 50
    iget-object v9, v0, Lh70/h;->j:Lvy0/b0;

    .line 51
    .line 52
    iget-object v10, v0, Lh70/h;->k:Lay0/a;

    .line 53
    .line 54
    iget-object v11, v0, Lh70/h;->l:Lay0/a;

    .line 55
    .line 56
    iget-object v12, v0, Lh70/h;->m:Lay0/a;

    .line 57
    .line 58
    iget-object v13, v0, Lh70/h;->n:Lay0/a;

    .line 59
    .line 60
    iget-object v14, v0, Lh70/h;->o:Lay0/k;

    .line 61
    .line 62
    iget-object v15, v0, Lh70/h;->p:Lay0/a;

    .line 63
    .line 64
    iget-object v2, v0, Lh70/h;->q:Lay0/k;

    .line 65
    .line 66
    iget-object v0, v0, Lh70/h;->r:Lay0/a;

    .line 67
    .line 68
    move-object/from16 v17, v0

    .line 69
    .line 70
    move-object/from16 v18, v1

    .line 71
    .line 72
    move-object/from16 v16, v2

    .line 73
    .line 74
    invoke-static/range {v4 .. v19}, Lh70/m;->a(Lg61/q;Lg61/p;ZLay0/k;Lay0/a;Lvy0/b0;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    move-object/from16 v18, v1

    .line 79
    .line 80
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 81
    .line 82
    .line 83
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object v0

    .line 86
    :pswitch_0
    move-object/from16 v15, p1

    .line 87
    .line 88
    check-cast v15, Ll2/o;

    .line 89
    .line 90
    move-object/from16 v1, p2

    .line 91
    .line 92
    check-cast v1, Ljava/lang/Integer;

    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    const/4 v1, 0x1

    .line 98
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result v16

    .line 102
    iget-object v1, v0, Lh70/h;->e:Lg61/q;

    .line 103
    .line 104
    iget-object v2, v0, Lh70/h;->f:Lg61/p;

    .line 105
    .line 106
    iget-boolean v3, v0, Lh70/h;->g:Z

    .line 107
    .line 108
    iget-object v4, v0, Lh70/h;->h:Lay0/k;

    .line 109
    .line 110
    iget-object v5, v0, Lh70/h;->i:Lay0/a;

    .line 111
    .line 112
    iget-object v6, v0, Lh70/h;->j:Lvy0/b0;

    .line 113
    .line 114
    iget-object v7, v0, Lh70/h;->k:Lay0/a;

    .line 115
    .line 116
    iget-object v8, v0, Lh70/h;->l:Lay0/a;

    .line 117
    .line 118
    iget-object v9, v0, Lh70/h;->m:Lay0/a;

    .line 119
    .line 120
    iget-object v10, v0, Lh70/h;->n:Lay0/a;

    .line 121
    .line 122
    iget-object v11, v0, Lh70/h;->o:Lay0/k;

    .line 123
    .line 124
    iget-object v12, v0, Lh70/h;->p:Lay0/a;

    .line 125
    .line 126
    iget-object v13, v0, Lh70/h;->q:Lay0/k;

    .line 127
    .line 128
    iget-object v14, v0, Lh70/h;->r:Lay0/a;

    .line 129
    .line 130
    invoke-static/range {v1 .. v16}, Lh70/m;->a(Lg61/q;Lg61/p;ZLay0/k;Lay0/a;Lvy0/b0;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 131
    .line 132
    .line 133
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    return-object v0

    .line 136
    nop

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
