.class public final synthetic Lp1/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lp1/v;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lk1/z0;

.field public final synthetic h:Lp1/f;

.field public final synthetic i:F

.field public final synthetic j:Lx2/i;

.field public final synthetic k:Lh1/g;

.field public final synthetic l:Z

.field public final synthetic m:Z

.field public final synthetic n:Lo3/a;

.field public final synthetic o:Lh1/n;

.field public final synthetic p:Le1/j;

.field public final synthetic q:Lt2/b;

.field public final synthetic r:I

.field public final synthetic s:I


# direct methods
.method public synthetic constructor <init>(Lp1/v;Lx2/s;Lk1/z0;Lp1/f;FLx2/i;Lh1/g;ZZLo3/a;Lh1/n;Le1/j;Lt2/b;II)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lp1/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lp1/c;->e:Lp1/v;

    iput-object p2, p0, Lp1/c;->f:Lx2/s;

    iput-object p3, p0, Lp1/c;->g:Lk1/z0;

    iput-object p4, p0, Lp1/c;->h:Lp1/f;

    iput p5, p0, Lp1/c;->i:F

    iput-object p6, p0, Lp1/c;->j:Lx2/i;

    iput-object p7, p0, Lp1/c;->k:Lh1/g;

    iput-boolean p8, p0, Lp1/c;->l:Z

    iput-boolean p9, p0, Lp1/c;->m:Z

    iput-object p10, p0, Lp1/c;->n:Lo3/a;

    iput-object p11, p0, Lp1/c;->o:Lh1/n;

    iput-object p12, p0, Lp1/c;->p:Le1/j;

    iput-object p13, p0, Lp1/c;->q:Lt2/b;

    iput p14, p0, Lp1/c;->r:I

    move/from16 p1, p15

    iput p1, p0, Lp1/c;->s:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lp1/v;Lk1/z0;ZLh1/g;ZLe1/j;FLp1/f;Lo3/a;Lx2/i;Lh1/n;Lt2/b;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lp1/c;->d:I

    sget-object v0, Lg1/w1;->d:Lg1/w1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lp1/c;->f:Lx2/s;

    iput-object p2, p0, Lp1/c;->e:Lp1/v;

    iput-object p3, p0, Lp1/c;->g:Lk1/z0;

    iput-boolean p4, p0, Lp1/c;->l:Z

    iput-object p5, p0, Lp1/c;->k:Lh1/g;

    iput-boolean p6, p0, Lp1/c;->m:Z

    iput-object p7, p0, Lp1/c;->p:Le1/j;

    iput p8, p0, Lp1/c;->i:F

    iput-object p9, p0, Lp1/c;->h:Lp1/f;

    iput-object p10, p0, Lp1/c;->n:Lo3/a;

    iput-object p11, p0, Lp1/c;->j:Lx2/i;

    iput-object p12, p0, Lp1/c;->o:Lh1/n;

    iput-object p13, p0, Lp1/c;->q:Lt2/b;

    iput p14, p0, Lp1/c;->r:I

    move/from16 p1, p15

    iput p1, p0, Lp1/c;->s:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lp1/c;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget v3, v0, Lp1/c;->r:I

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v11, p1

    .line 13
    .line 14
    check-cast v11, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v1, p2

    .line 17
    .line 18
    check-cast v1, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    or-int/lit8 v1, v3, 0x1

    .line 24
    .line 25
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    iget v4, v0, Lp1/c;->i:F

    .line 30
    .line 31
    iget v6, v0, Lp1/c;->s:I

    .line 32
    .line 33
    iget-object v7, v0, Lp1/c;->p:Le1/j;

    .line 34
    .line 35
    iget-object v8, v0, Lp1/c;->k:Lh1/g;

    .line 36
    .line 37
    iget-object v9, v0, Lp1/c;->o:Lh1/n;

    .line 38
    .line 39
    iget-object v10, v0, Lp1/c;->g:Lk1/z0;

    .line 40
    .line 41
    iget-object v12, v0, Lp1/c;->n:Lo3/a;

    .line 42
    .line 43
    iget-object v13, v0, Lp1/c;->h:Lp1/f;

    .line 44
    .line 45
    iget-object v14, v0, Lp1/c;->e:Lp1/v;

    .line 46
    .line 47
    iget-object v15, v0, Lp1/c;->q:Lt2/b;

    .line 48
    .line 49
    iget-object v1, v0, Lp1/c;->j:Lx2/i;

    .line 50
    .line 51
    iget-object v3, v0, Lp1/c;->f:Lx2/s;

    .line 52
    .line 53
    move-object/from16 v16, v1

    .line 54
    .line 55
    iget-boolean v1, v0, Lp1/c;->l:Z

    .line 56
    .line 57
    iget-boolean v0, v0, Lp1/c;->m:Z

    .line 58
    .line 59
    move/from16 v19, v0

    .line 60
    .line 61
    move/from16 v18, v1

    .line 62
    .line 63
    move-object/from16 v17, v3

    .line 64
    .line 65
    invoke-static/range {v4 .. v19}, Ljp/ad;->b(FIILe1/j;Lh1/g;Lh1/n;Lk1/z0;Ll2/o;Lo3/a;Lp1/f;Lp1/v;Lt2/b;Lx2/i;Lx2/s;ZZ)V

    .line 66
    .line 67
    .line 68
    return-object v2

    .line 69
    :pswitch_0
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 70
    .line 71
    move-object/from16 v11, p1

    .line 72
    .line 73
    check-cast v11, Ll2/o;

    .line 74
    .line 75
    move-object/from16 v1, p2

    .line 76
    .line 77
    check-cast v1, Ljava/lang/Integer;

    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    or-int/lit8 v1, v3, 0x1

    .line 83
    .line 84
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    iget v1, v0, Lp1/c;->s:I

    .line 89
    .line 90
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 91
    .line 92
    .line 93
    move-result v6

    .line 94
    iget v4, v0, Lp1/c;->i:F

    .line 95
    .line 96
    iget-object v7, v0, Lp1/c;->p:Le1/j;

    .line 97
    .line 98
    iget-object v8, v0, Lp1/c;->k:Lh1/g;

    .line 99
    .line 100
    iget-object v9, v0, Lp1/c;->o:Lh1/n;

    .line 101
    .line 102
    iget-object v10, v0, Lp1/c;->g:Lk1/z0;

    .line 103
    .line 104
    iget-object v12, v0, Lp1/c;->n:Lo3/a;

    .line 105
    .line 106
    iget-object v13, v0, Lp1/c;->h:Lp1/f;

    .line 107
    .line 108
    iget-object v14, v0, Lp1/c;->e:Lp1/v;

    .line 109
    .line 110
    iget-object v15, v0, Lp1/c;->q:Lt2/b;

    .line 111
    .line 112
    iget-object v1, v0, Lp1/c;->j:Lx2/i;

    .line 113
    .line 114
    iget-object v3, v0, Lp1/c;->f:Lx2/s;

    .line 115
    .line 116
    move-object/from16 v16, v1

    .line 117
    .line 118
    iget-boolean v1, v0, Lp1/c;->l:Z

    .line 119
    .line 120
    iget-boolean v0, v0, Lp1/c;->m:Z

    .line 121
    .line 122
    move/from16 v19, v0

    .line 123
    .line 124
    move/from16 v18, v1

    .line 125
    .line 126
    move-object/from16 v17, v3

    .line 127
    .line 128
    invoke-static/range {v4 .. v19}, Ljp/zc;->b(FIILe1/j;Lh1/g;Lh1/n;Lk1/z0;Ll2/o;Lo3/a;Lp1/f;Lp1/v;Lt2/b;Lx2/i;Lx2/s;ZZ)V

    .line 129
    .line 130
    .line 131
    return-object v2

    .line 132
    nop

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
