.class public final synthetic Li91/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lx4/p;

.field public final synthetic m:Ljava/lang/String;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:Ljava/lang/String;

.field public final synthetic p:Ljava/lang/String;

.field public final synthetic q:Ljava/lang/String;

.field public final synthetic r:I

.field public final synthetic s:I

.field public final synthetic t:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/l0;->d:Ljava/lang/String;

    iput-object p2, p0, Li91/l0;->e:Ljava/lang/String;

    iput-object p3, p0, Li91/l0;->f:Lay0/a;

    iput-object p4, p0, Li91/l0;->g:Ljava/lang/String;

    iput-object p5, p0, Li91/l0;->h:Lx2/s;

    iput-object p6, p0, Li91/l0;->i:Lay0/a;

    iput-object p7, p0, Li91/l0;->j:Ljava/lang/String;

    iput-object p8, p0, Li91/l0;->k:Lay0/a;

    iput-object p9, p0, Li91/l0;->l:Lx4/p;

    iput-object p10, p0, Li91/l0;->m:Ljava/lang/String;

    iput-object p11, p0, Li91/l0;->n:Ljava/lang/String;

    iput-object p12, p0, Li91/l0;->o:Ljava/lang/String;

    iput-object p13, p0, Li91/l0;->p:Ljava/lang/String;

    iput-object p14, p0, Li91/l0;->q:Ljava/lang/String;

    iput p15, p0, Li91/l0;->r:I

    move/from16 p1, p16

    iput p1, p0, Li91/l0;->s:I

    move/from16 p1, p17

    iput p1, p0, Li91/l0;->t:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v14, p1

    .line 4
    .line 5
    check-cast v14, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget v1, v0, Li91/l0;->r:I

    .line 15
    .line 16
    or-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v15

    .line 22
    iget v1, v0, Li91/l0;->s:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v16

    .line 28
    iget-object v1, v0, Li91/l0;->d:Ljava/lang/String;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Li91/l0;->e:Ljava/lang/String;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Li91/l0;->f:Lay0/a;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget-object v3, v0, Li91/l0;->g:Ljava/lang/String;

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-object v4, v0, Li91/l0;->h:Lx2/s;

    .line 41
    .line 42
    move-object v6, v5

    .line 43
    iget-object v5, v0, Li91/l0;->i:Lay0/a;

    .line 44
    .line 45
    move-object v7, v6

    .line 46
    iget-object v6, v0, Li91/l0;->j:Ljava/lang/String;

    .line 47
    .line 48
    move-object v8, v7

    .line 49
    iget-object v7, v0, Li91/l0;->k:Lay0/a;

    .line 50
    .line 51
    move-object v9, v8

    .line 52
    iget-object v8, v0, Li91/l0;->l:Lx4/p;

    .line 53
    .line 54
    move-object v10, v9

    .line 55
    iget-object v9, v0, Li91/l0;->m:Ljava/lang/String;

    .line 56
    .line 57
    move-object v11, v10

    .line 58
    iget-object v10, v0, Li91/l0;->n:Ljava/lang/String;

    .line 59
    .line 60
    move-object v12, v11

    .line 61
    iget-object v11, v0, Li91/l0;->o:Ljava/lang/String;

    .line 62
    .line 63
    move-object v13, v12

    .line 64
    iget-object v12, v0, Li91/l0;->p:Ljava/lang/String;

    .line 65
    .line 66
    move-object/from16 v17, v13

    .line 67
    .line 68
    iget-object v13, v0, Li91/l0;->q:Ljava/lang/String;

    .line 69
    .line 70
    iget v0, v0, Li91/l0;->t:I

    .line 71
    .line 72
    move-object/from16 v18, v17

    .line 73
    .line 74
    move/from16 v17, v0

    .line 75
    .line 76
    move-object/from16 v0, v18

    .line 77
    .line 78
    invoke-static/range {v0 .. v17}, Li91/j0;->d(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;III)V

    .line 79
    .line 80
    .line 81
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object v0
.end method
