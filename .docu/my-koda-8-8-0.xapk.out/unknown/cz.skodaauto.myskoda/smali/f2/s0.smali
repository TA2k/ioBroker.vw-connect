.class public final synthetic Lf2/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lg4/p0;

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:Lr4/k;

.field public final synthetic k:J

.field public final synthetic l:I

.field public final synthetic m:Z

.field public final synthetic n:I

.field public final synthetic o:Lay0/k;

.field public final synthetic p:I

.field public final synthetic q:I

.field public final synthetic r:Ljava/lang/CharSequence;


# direct methods
.method public synthetic constructor <init>(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;II)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lf2/s0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/s0;->r:Ljava/lang/CharSequence;

    iput-object p2, p0, Lf2/s0;->e:Lx2/s;

    iput-object p3, p0, Lf2/s0;->f:Lg4/p0;

    iput-wide p4, p0, Lf2/s0;->g:J

    iput-wide p6, p0, Lf2/s0;->h:J

    iput-wide p8, p0, Lf2/s0;->i:J

    iput-object p10, p0, Lf2/s0;->j:Lr4/k;

    iput-wide p11, p0, Lf2/s0;->k:J

    iput p13, p0, Lf2/s0;->l:I

    iput-boolean p14, p0, Lf2/s0;->m:Z

    move/from16 p1, p15

    iput p1, p0, Lf2/s0;->n:I

    move-object/from16 p1, p16

    iput-object p1, p0, Lf2/s0;->o:Lay0/k;

    move/from16 p1, p17

    iput p1, p0, Lf2/s0;->p:I

    move/from16 p1, p18

    iput p1, p0, Lf2/s0;->q:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;JJJLr4/k;JIZILay0/k;Lg4/p0;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lf2/s0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/s0;->r:Ljava/lang/CharSequence;

    iput-object p2, p0, Lf2/s0;->e:Lx2/s;

    iput-wide p3, p0, Lf2/s0;->g:J

    iput-wide p5, p0, Lf2/s0;->h:J

    iput-wide p7, p0, Lf2/s0;->i:J

    iput-object p9, p0, Lf2/s0;->j:Lr4/k;

    iput-wide p10, p0, Lf2/s0;->k:J

    iput p12, p0, Lf2/s0;->l:I

    iput-boolean p13, p0, Lf2/s0;->m:Z

    iput p14, p0, Lf2/s0;->n:I

    move-object/from16 p1, p15

    iput-object p1, p0, Lf2/s0;->o:Lay0/k;

    move-object/from16 p1, p16

    iput-object p1, p0, Lf2/s0;->f:Lg4/p0;

    move/from16 p1, p17

    iput p1, p0, Lf2/s0;->p:I

    move/from16 p1, p18

    iput p1, p0, Lf2/s0;->q:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf2/s0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lf2/s0;->r:Ljava/lang/CharSequence;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Lg4/g;

    .line 12
    .line 13
    move-object/from16 v18, p1

    .line 14
    .line 15
    check-cast v18, Ll2/o;

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
    iget v1, v0, Lf2/s0;->p:I

    .line 25
    .line 26
    or-int/lit8 v1, v1, 0x1

    .line 27
    .line 28
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v19

    .line 32
    iget v1, v0, Lf2/s0;->q:I

    .line 33
    .line 34
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result v20

    .line 38
    iget-object v3, v0, Lf2/s0;->e:Lx2/s;

    .line 39
    .line 40
    iget-object v4, v0, Lf2/s0;->f:Lg4/p0;

    .line 41
    .line 42
    iget-wide v5, v0, Lf2/s0;->g:J

    .line 43
    .line 44
    iget-wide v7, v0, Lf2/s0;->h:J

    .line 45
    .line 46
    iget-wide v9, v0, Lf2/s0;->i:J

    .line 47
    .line 48
    iget-object v11, v0, Lf2/s0;->j:Lr4/k;

    .line 49
    .line 50
    iget-wide v12, v0, Lf2/s0;->k:J

    .line 51
    .line 52
    iget v14, v0, Lf2/s0;->l:I

    .line 53
    .line 54
    iget-boolean v15, v0, Lf2/s0;->m:Z

    .line 55
    .line 56
    iget v1, v0, Lf2/s0;->n:I

    .line 57
    .line 58
    iget-object v0, v0, Lf2/s0;->o:Lay0/k;

    .line 59
    .line 60
    move-object/from16 v17, v0

    .line 61
    .line 62
    move/from16 v16, v1

    .line 63
    .line 64
    invoke-static/range {v2 .. v20}, Li91/z3;->a(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;II)V

    .line 65
    .line 66
    .line 67
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object v0

    .line 70
    :pswitch_0
    iget-object v1, v0, Lf2/s0;->r:Ljava/lang/CharSequence;

    .line 71
    .line 72
    move-object v2, v1

    .line 73
    check-cast v2, Ljava/lang/String;

    .line 74
    .line 75
    move-object/from16 v18, p1

    .line 76
    .line 77
    check-cast v18, Ll2/o;

    .line 78
    .line 79
    move-object/from16 v1, p2

    .line 80
    .line 81
    check-cast v1, Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    iget v1, v0, Lf2/s0;->p:I

    .line 87
    .line 88
    or-int/lit8 v1, v1, 0x1

    .line 89
    .line 90
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 91
    .line 92
    .line 93
    move-result v19

    .line 94
    iget-object v3, v0, Lf2/s0;->e:Lx2/s;

    .line 95
    .line 96
    iget-wide v4, v0, Lf2/s0;->g:J

    .line 97
    .line 98
    iget-wide v6, v0, Lf2/s0;->h:J

    .line 99
    .line 100
    iget-wide v8, v0, Lf2/s0;->i:J

    .line 101
    .line 102
    iget-object v10, v0, Lf2/s0;->j:Lr4/k;

    .line 103
    .line 104
    iget-wide v11, v0, Lf2/s0;->k:J

    .line 105
    .line 106
    iget v13, v0, Lf2/s0;->l:I

    .line 107
    .line 108
    iget-boolean v14, v0, Lf2/s0;->m:Z

    .line 109
    .line 110
    iget v15, v0, Lf2/s0;->n:I

    .line 111
    .line 112
    iget-object v1, v0, Lf2/s0;->o:Lay0/k;

    .line 113
    .line 114
    move-object/from16 v16, v1

    .line 115
    .line 116
    iget-object v1, v0, Lf2/s0;->f:Lg4/p0;

    .line 117
    .line 118
    iget v0, v0, Lf2/s0;->q:I

    .line 119
    .line 120
    move/from16 v20, v0

    .line 121
    .line 122
    move-object/from16 v17, v1

    .line 123
    .line 124
    invoke-static/range {v2 .. v20}, Lf2/v0;->c(Ljava/lang/String;Lx2/s;JJJLr4/k;JIZILay0/k;Lg4/p0;Ll2/o;II)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
