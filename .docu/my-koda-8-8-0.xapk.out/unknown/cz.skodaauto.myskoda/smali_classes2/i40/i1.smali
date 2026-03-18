.class public final synthetic Li40/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/u1;

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

.field public final synthetic q:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/u1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p15, p0, Li40/i1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/i1;->e:Lh40/u1;

    .line 4
    .line 5
    iput-object p2, p0, Li40/i1;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Li40/i1;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Li40/i1;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Li40/i1;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Li40/i1;->j:Lay0/a;

    .line 14
    .line 15
    iput-object p7, p0, Li40/i1;->k:Lay0/a;

    .line 16
    .line 17
    iput-object p8, p0, Li40/i1;->l:Lay0/a;

    .line 18
    .line 19
    iput-object p9, p0, Li40/i1;->m:Lay0/a;

    .line 20
    .line 21
    iput-object p10, p0, Li40/i1;->n:Lay0/a;

    .line 22
    .line 23
    iput-object p11, p0, Li40/i1;->o:Lay0/a;

    .line 24
    .line 25
    iput-object p12, p0, Li40/i1;->p:Lay0/a;

    .line 26
    .line 27
    iput-object p13, p0, Li40/i1;->q:Lay0/a;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/i1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v15, p1

    .line 9
    .line 10
    check-cast v15, Ll2/o;

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
    const/4 v1, 0x1

    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v16

    .line 24
    iget-object v2, v0, Li40/i1;->e:Lh40/u1;

    .line 25
    .line 26
    iget-object v3, v0, Li40/i1;->f:Lay0/a;

    .line 27
    .line 28
    iget-object v4, v0, Li40/i1;->g:Lay0/a;

    .line 29
    .line 30
    iget-object v5, v0, Li40/i1;->h:Lay0/a;

    .line 31
    .line 32
    iget-object v6, v0, Li40/i1;->i:Lay0/a;

    .line 33
    .line 34
    iget-object v7, v0, Li40/i1;->j:Lay0/a;

    .line 35
    .line 36
    iget-object v8, v0, Li40/i1;->k:Lay0/a;

    .line 37
    .line 38
    iget-object v9, v0, Li40/i1;->l:Lay0/a;

    .line 39
    .line 40
    iget-object v10, v0, Li40/i1;->m:Lay0/a;

    .line 41
    .line 42
    iget-object v11, v0, Li40/i1;->n:Lay0/a;

    .line 43
    .line 44
    iget-object v12, v0, Li40/i1;->o:Lay0/a;

    .line 45
    .line 46
    iget-object v13, v0, Li40/i1;->p:Lay0/a;

    .line 47
    .line 48
    iget-object v14, v0, Li40/i1;->q:Lay0/a;

    .line 49
    .line 50
    invoke-static/range {v2 .. v16}, Li40/l1;->q(Lh40/u1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object v0

    .line 56
    :pswitch_0
    move-object/from16 v14, p1

    .line 57
    .line 58
    check-cast v14, Ll2/o;

    .line 59
    .line 60
    move-object/from16 v1, p2

    .line 61
    .line 62
    check-cast v1, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const/4 v1, 0x1

    .line 68
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 69
    .line 70
    .line 71
    move-result v15

    .line 72
    iget-object v1, v0, Li40/i1;->e:Lh40/u1;

    .line 73
    .line 74
    iget-object v2, v0, Li40/i1;->f:Lay0/a;

    .line 75
    .line 76
    iget-object v3, v0, Li40/i1;->g:Lay0/a;

    .line 77
    .line 78
    iget-object v4, v0, Li40/i1;->h:Lay0/a;

    .line 79
    .line 80
    iget-object v5, v0, Li40/i1;->i:Lay0/a;

    .line 81
    .line 82
    iget-object v6, v0, Li40/i1;->j:Lay0/a;

    .line 83
    .line 84
    iget-object v7, v0, Li40/i1;->k:Lay0/a;

    .line 85
    .line 86
    iget-object v8, v0, Li40/i1;->l:Lay0/a;

    .line 87
    .line 88
    iget-object v9, v0, Li40/i1;->m:Lay0/a;

    .line 89
    .line 90
    iget-object v10, v0, Li40/i1;->n:Lay0/a;

    .line 91
    .line 92
    iget-object v11, v0, Li40/i1;->o:Lay0/a;

    .line 93
    .line 94
    iget-object v12, v0, Li40/i1;->p:Lay0/a;

    .line 95
    .line 96
    iget-object v13, v0, Li40/i1;->q:Lay0/a;

    .line 97
    .line 98
    invoke-static/range {v1 .. v15}, Li40/l1;->q(Lh40/u1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
