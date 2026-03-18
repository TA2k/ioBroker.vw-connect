.class public final synthetic Lxf0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Z

.field public final synthetic k:Le3/s;

.field public final synthetic l:J

.field public final synthetic m:Z

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:Ljava/lang/String;

.field public final synthetic q:Lx2/s;

.field public final synthetic r:I

.field public final synthetic s:I

.field public final synthetic t:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lx2/s;Ljava/lang/String;ZZZLe3/s;JZLay0/k;Lay0/a;Ljava/lang/String;Lx2/s;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/t0;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/t0;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/t0;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/t0;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-boolean p5, p0, Lxf0/t0;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lxf0/t0;->i:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Lxf0/t0;->j:Z

    .line 17
    .line 18
    iput-object p8, p0, Lxf0/t0;->k:Le3/s;

    .line 19
    .line 20
    iput-wide p9, p0, Lxf0/t0;->l:J

    .line 21
    .line 22
    iput-boolean p11, p0, Lxf0/t0;->m:Z

    .line 23
    .line 24
    iput-object p12, p0, Lxf0/t0;->n:Lay0/k;

    .line 25
    .line 26
    iput-object p13, p0, Lxf0/t0;->o:Lay0/a;

    .line 27
    .line 28
    iput-object p14, p0, Lxf0/t0;->p:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p15, p0, Lxf0/t0;->q:Lx2/s;

    .line 31
    .line 32
    move/from16 p1, p16

    .line 33
    .line 34
    iput p1, p0, Lxf0/t0;->r:I

    .line 35
    .line 36
    move/from16 p1, p17

    .line 37
    .line 38
    iput p1, p0, Lxf0/t0;->s:I

    .line 39
    .line 40
    move/from16 p1, p18

    .line 41
    .line 42
    iput p1, p0, Lxf0/t0;->t:I

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v15, p1

    .line 4
    .line 5
    check-cast v15, Ll2/o;

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
    iget v1, v0, Lxf0/t0;->r:I

    .line 15
    .line 16
    or-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v16

    .line 22
    iget v1, v0, Lxf0/t0;->s:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v17

    .line 28
    iget-object v1, v0, Lxf0/t0;->d:Ljava/lang/String;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Lxf0/t0;->e:Ljava/lang/String;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Lxf0/t0;->f:Lx2/s;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget-object v3, v0, Lxf0/t0;->g:Ljava/lang/String;

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-boolean v4, v0, Lxf0/t0;->h:Z

    .line 41
    .line 42
    move-object v6, v5

    .line 43
    iget-boolean v5, v0, Lxf0/t0;->i:Z

    .line 44
    .line 45
    move-object v7, v6

    .line 46
    iget-boolean v6, v0, Lxf0/t0;->j:Z

    .line 47
    .line 48
    move-object v8, v7

    .line 49
    iget-object v7, v0, Lxf0/t0;->k:Le3/s;

    .line 50
    .line 51
    move-object v10, v8

    .line 52
    iget-wide v8, v0, Lxf0/t0;->l:J

    .line 53
    .line 54
    move-object v11, v10

    .line 55
    iget-boolean v10, v0, Lxf0/t0;->m:Z

    .line 56
    .line 57
    move-object v12, v11

    .line 58
    iget-object v11, v0, Lxf0/t0;->n:Lay0/k;

    .line 59
    .line 60
    move-object v13, v12

    .line 61
    iget-object v12, v0, Lxf0/t0;->o:Lay0/a;

    .line 62
    .line 63
    move-object v14, v13

    .line 64
    iget-object v13, v0, Lxf0/t0;->p:Ljava/lang/String;

    .line 65
    .line 66
    move-object/from16 v18, v14

    .line 67
    .line 68
    iget-object v14, v0, Lxf0/t0;->q:Lx2/s;

    .line 69
    .line 70
    iget v0, v0, Lxf0/t0;->t:I

    .line 71
    .line 72
    move-object/from16 v19, v18

    .line 73
    .line 74
    move/from16 v18, v0

    .line 75
    .line 76
    move-object/from16 v0, v19

    .line 77
    .line 78
    invoke-static/range {v0 .. v18}, Lxf0/i0;->r(Ljava/lang/String;Ljava/lang/String;Lx2/s;Ljava/lang/String;ZZZLe3/s;JZLay0/k;Lay0/a;Ljava/lang/String;Lx2/s;Ll2/o;III)V

    .line 79
    .line 80
    .line 81
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object v0
.end method
