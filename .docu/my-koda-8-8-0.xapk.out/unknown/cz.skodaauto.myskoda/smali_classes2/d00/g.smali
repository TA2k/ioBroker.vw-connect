.class public final synthetic Ld00/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:Lay0/a;

.field public final synthetic q:I

.field public final synthetic r:I

.field public final synthetic s:Lql0/h;


# direct methods
.method public synthetic constructor <init>(Lc00/d0;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;II)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld00/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/g;->s:Lql0/h;

    iput-object p2, p0, Ld00/g;->e:Lay0/a;

    iput-object p3, p0, Ld00/g;->f:Lay0/a;

    iput-object p4, p0, Ld00/g;->g:Lay0/a;

    iput-object p5, p0, Ld00/g;->h:Lay0/a;

    iput-object p6, p0, Ld00/g;->i:Lay0/a;

    iput-object p7, p0, Ld00/g;->j:Lay0/a;

    iput-object p8, p0, Ld00/g;->k:Lay0/a;

    iput-object p9, p0, Ld00/g;->l:Lay0/a;

    iput-object p10, p0, Ld00/g;->m:Lay0/a;

    iput-object p11, p0, Ld00/g;->n:Lay0/a;

    iput-object p12, p0, Ld00/g;->o:Lay0/a;

    iput-object p13, p0, Ld00/g;->p:Lay0/a;

    iput p14, p0, Ld00/g;->q:I

    move/from16 p1, p15

    iput p1, p0, Ld00/g;->r:I

    return-void
.end method

.method public synthetic constructor <init>(Lnz/s;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;II)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ld00/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/g;->s:Lql0/h;

    iput-object p2, p0, Ld00/g;->e:Lay0/a;

    iput-object p3, p0, Ld00/g;->f:Lay0/a;

    iput-object p4, p0, Ld00/g;->g:Lay0/a;

    iput-object p5, p0, Ld00/g;->h:Lay0/a;

    iput-object p6, p0, Ld00/g;->i:Lay0/a;

    iput-object p7, p0, Ld00/g;->j:Lay0/a;

    iput-object p8, p0, Ld00/g;->k:Lay0/a;

    iput-object p9, p0, Ld00/g;->l:Lay0/a;

    iput-object p10, p0, Ld00/g;->m:Lay0/a;

    iput-object p11, p0, Ld00/g;->n:Lay0/a;

    iput-object p12, p0, Ld00/g;->o:Lay0/a;

    iput-object p13, p0, Ld00/g;->p:Lay0/a;

    iput p14, p0, Ld00/g;->q:I

    move/from16 p1, p15

    iput p1, p0, Ld00/g;->r:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld00/g;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Ld00/g;->s:Lql0/h;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Lnz/s;

    .line 12
    .line 13
    move-object/from16 v15, p1

    .line 14
    .line 15
    check-cast v15, Ll2/o;

    .line 16
    .line 17
    move-object/from16 v1, p2

    .line 18
    .line 19
    check-cast v1, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget v1, v0, Ld00/g;->q:I

    .line 25
    .line 26
    or-int/lit8 v1, v1, 0x1

    .line 27
    .line 28
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v16

    .line 32
    iget v1, v0, Ld00/g;->r:I

    .line 33
    .line 34
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result v17

    .line 38
    iget-object v3, v0, Ld00/g;->e:Lay0/a;

    .line 39
    .line 40
    iget-object v4, v0, Ld00/g;->f:Lay0/a;

    .line 41
    .line 42
    iget-object v5, v0, Ld00/g;->g:Lay0/a;

    .line 43
    .line 44
    iget-object v6, v0, Ld00/g;->h:Lay0/a;

    .line 45
    .line 46
    iget-object v7, v0, Ld00/g;->i:Lay0/a;

    .line 47
    .line 48
    iget-object v8, v0, Ld00/g;->j:Lay0/a;

    .line 49
    .line 50
    iget-object v9, v0, Ld00/g;->k:Lay0/a;

    .line 51
    .line 52
    iget-object v10, v0, Ld00/g;->l:Lay0/a;

    .line 53
    .line 54
    iget-object v11, v0, Ld00/g;->m:Lay0/a;

    .line 55
    .line 56
    iget-object v12, v0, Ld00/g;->n:Lay0/a;

    .line 57
    .line 58
    iget-object v13, v0, Ld00/g;->o:Lay0/a;

    .line 59
    .line 60
    iget-object v14, v0, Ld00/g;->p:Lay0/a;

    .line 61
    .line 62
    invoke-static/range {v2 .. v17}, Loz/e;->e(Lnz/s;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 63
    .line 64
    .line 65
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object v0

    .line 68
    :pswitch_0
    iget-object v1, v0, Ld00/g;->s:Lql0/h;

    .line 69
    .line 70
    move-object v2, v1

    .line 71
    check-cast v2, Lc00/d0;

    .line 72
    .line 73
    move-object/from16 v15, p1

    .line 74
    .line 75
    check-cast v15, Ll2/o;

    .line 76
    .line 77
    move-object/from16 v1, p2

    .line 78
    .line 79
    check-cast v1, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    iget v1, v0, Ld00/g;->q:I

    .line 85
    .line 86
    or-int/lit8 v1, v1, 0x1

    .line 87
    .line 88
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 89
    .line 90
    .line 91
    move-result v16

    .line 92
    iget v1, v0, Ld00/g;->r:I

    .line 93
    .line 94
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 95
    .line 96
    .line 97
    move-result v17

    .line 98
    iget-object v3, v0, Ld00/g;->e:Lay0/a;

    .line 99
    .line 100
    iget-object v4, v0, Ld00/g;->f:Lay0/a;

    .line 101
    .line 102
    iget-object v5, v0, Ld00/g;->g:Lay0/a;

    .line 103
    .line 104
    iget-object v6, v0, Ld00/g;->h:Lay0/a;

    .line 105
    .line 106
    iget-object v7, v0, Ld00/g;->i:Lay0/a;

    .line 107
    .line 108
    iget-object v8, v0, Ld00/g;->j:Lay0/a;

    .line 109
    .line 110
    iget-object v9, v0, Ld00/g;->k:Lay0/a;

    .line 111
    .line 112
    iget-object v10, v0, Ld00/g;->l:Lay0/a;

    .line 113
    .line 114
    iget-object v11, v0, Ld00/g;->m:Lay0/a;

    .line 115
    .line 116
    iget-object v12, v0, Ld00/g;->n:Lay0/a;

    .line 117
    .line 118
    iget-object v13, v0, Ld00/g;->o:Lay0/a;

    .line 119
    .line 120
    iget-object v14, v0, Ld00/g;->p:Lay0/a;

    .line 121
    .line 122
    invoke-static/range {v2 .. v17}, Ld00/o;->m(Lc00/d0;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
