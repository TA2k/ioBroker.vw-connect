.class public final synthetic Lyg0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lx2/s;

.field public final synthetic l:Ljava/lang/String;

.field public final synthetic m:Ljava/lang/String;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/n;

.field public final synthetic p:I

.field public final synthetic q:I

.field public final synthetic r:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lx2/s;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/n;IIII)V
    .locals 1

    .line 1
    move/from16 v0, p15

    .line 2
    .line 3
    iput v0, p0, Lyg0/e;->d:I

    .line 4
    .line 5
    iput-object p1, p0, Lyg0/e;->e:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p2, p0, Lyg0/e;->f:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p3, p0, Lyg0/e;->g:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p4, p0, Lyg0/e;->h:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p5, p0, Lyg0/e;->i:Ljava/lang/String;

    .line 14
    .line 15
    iput-object p6, p0, Lyg0/e;->j:Lay0/a;

    .line 16
    .line 17
    iput-object p7, p0, Lyg0/e;->k:Lx2/s;

    .line 18
    .line 19
    iput-object p8, p0, Lyg0/e;->l:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p9, p0, Lyg0/e;->m:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p10, p0, Lyg0/e;->n:Lay0/a;

    .line 24
    .line 25
    iput-object p11, p0, Lyg0/e;->o:Lay0/n;

    .line 26
    .line 27
    iput p12, p0, Lyg0/e;->p:I

    .line 28
    .line 29
    iput p13, p0, Lyg0/e;->q:I

    .line 30
    .line 31
    iput p14, p0, Lyg0/e;->r:I

    .line 32
    .line 33
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 34
    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lyg0/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v13, p1

    .line 9
    .line 10
    check-cast v13, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget v1, v0, Lyg0/e;->p:I

    .line 20
    .line 21
    or-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 24
    .line 25
    .line 26
    move-result v14

    .line 27
    iget v1, v0, Lyg0/e;->q:I

    .line 28
    .line 29
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result v15

    .line 33
    iget-object v2, v0, Lyg0/e;->e:Ljava/lang/String;

    .line 34
    .line 35
    iget-object v3, v0, Lyg0/e;->f:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v4, v0, Lyg0/e;->g:Ljava/lang/String;

    .line 38
    .line 39
    iget-object v5, v0, Lyg0/e;->h:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v6, v0, Lyg0/e;->i:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v7, v0, Lyg0/e;->j:Lay0/a;

    .line 44
    .line 45
    iget-object v8, v0, Lyg0/e;->k:Lx2/s;

    .line 46
    .line 47
    iget-object v9, v0, Lyg0/e;->l:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v10, v0, Lyg0/e;->m:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v11, v0, Lyg0/e;->n:Lay0/a;

    .line 52
    .line 53
    iget-object v12, v0, Lyg0/e;->o:Lay0/n;

    .line 54
    .line 55
    iget v0, v0, Lyg0/e;->r:I

    .line 56
    .line 57
    move/from16 v16, v0

    .line 58
    .line 59
    invoke-static/range {v2 .. v16}, Lyg0/a;->b(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lx2/s;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/n;Ll2/o;III)V

    .line 60
    .line 61
    .line 62
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_0
    move-object/from16 v12, p1

    .line 66
    .line 67
    check-cast v12, Ll2/o;

    .line 68
    .line 69
    move-object/from16 v1, p2

    .line 70
    .line 71
    check-cast v1, Ljava/lang/Integer;

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    iget v1, v0, Lyg0/e;->p:I

    .line 77
    .line 78
    or-int/lit8 v1, v1, 0x1

    .line 79
    .line 80
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 81
    .line 82
    .line 83
    move-result v13

    .line 84
    iget v1, v0, Lyg0/e;->q:I

    .line 85
    .line 86
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 87
    .line 88
    .line 89
    move-result v14

    .line 90
    iget-object v1, v0, Lyg0/e;->e:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v2, v0, Lyg0/e;->f:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v3, v0, Lyg0/e;->g:Ljava/lang/String;

    .line 95
    .line 96
    iget-object v4, v0, Lyg0/e;->h:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v5, v0, Lyg0/e;->i:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v6, v0, Lyg0/e;->j:Lay0/a;

    .line 101
    .line 102
    iget-object v7, v0, Lyg0/e;->k:Lx2/s;

    .line 103
    .line 104
    iget-object v8, v0, Lyg0/e;->l:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v9, v0, Lyg0/e;->m:Ljava/lang/String;

    .line 107
    .line 108
    iget-object v10, v0, Lyg0/e;->n:Lay0/a;

    .line 109
    .line 110
    iget-object v11, v0, Lyg0/e;->o:Lay0/n;

    .line 111
    .line 112
    iget v15, v0, Lyg0/e;->r:I

    .line 113
    .line 114
    invoke-static/range {v1 .. v15}, Lyg0/a;->b(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lx2/s;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/n;Ll2/o;III)V

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
