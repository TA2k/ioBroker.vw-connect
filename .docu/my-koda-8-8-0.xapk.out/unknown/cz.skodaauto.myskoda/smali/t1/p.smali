.class public final synthetic Lt1/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ll4/v;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lg4/p0;

.field public final synthetic h:Ll4/d0;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Li1/l;

.field public final synthetic k:Le3/p0;

.field public final synthetic l:Z

.field public final synthetic m:I

.field public final synthetic n:I

.field public final synthetic o:Ll4/j;

.field public final synthetic p:Lt1/n0;

.field public final synthetic q:Z

.field public final synthetic r:Z

.field public final synthetic s:Lt2/b;

.field public final synthetic t:I

.field public final synthetic u:I


# direct methods
.method public synthetic constructor <init>(Ll4/v;Lay0/k;Lx2/s;Lg4/p0;Ll4/d0;Lay0/k;Li1/l;Le3/p0;ZIILl4/j;Lt1/n0;ZZLt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/p;->d:Ll4/v;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/p;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lt1/p;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p4, p0, Lt1/p;->g:Lg4/p0;

    .line 11
    .line 12
    iput-object p5, p0, Lt1/p;->h:Ll4/d0;

    .line 13
    .line 14
    iput-object p6, p0, Lt1/p;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p7, p0, Lt1/p;->j:Li1/l;

    .line 17
    .line 18
    iput-object p8, p0, Lt1/p;->k:Le3/p0;

    .line 19
    .line 20
    iput-boolean p9, p0, Lt1/p;->l:Z

    .line 21
    .line 22
    iput p10, p0, Lt1/p;->m:I

    .line 23
    .line 24
    iput p11, p0, Lt1/p;->n:I

    .line 25
    .line 26
    iput-object p12, p0, Lt1/p;->o:Ll4/j;

    .line 27
    .line 28
    iput-object p13, p0, Lt1/p;->p:Lt1/n0;

    .line 29
    .line 30
    iput-boolean p14, p0, Lt1/p;->q:Z

    .line 31
    .line 32
    iput-boolean p15, p0, Lt1/p;->r:Z

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lt1/p;->s:Lt2/b;

    .line 37
    .line 38
    move/from16 p1, p17

    .line 39
    .line 40
    iput p1, p0, Lt1/p;->t:I

    .line 41
    .line 42
    move/from16 p1, p18

    .line 43
    .line 44
    iput p1, p0, Lt1/p;->u:I

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v16, p1

    .line 4
    .line 5
    check-cast v16, Ll2/o;

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
    iget v1, v0, Lt1/p;->t:I

    .line 15
    .line 16
    or-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v17

    .line 22
    iget v1, v0, Lt1/p;->u:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v18

    .line 28
    iget-object v1, v0, Lt1/p;->d:Ll4/v;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Lt1/p;->e:Lay0/k;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Lt1/p;->f:Lx2/s;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget-object v3, v0, Lt1/p;->g:Lg4/p0;

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-object v4, v0, Lt1/p;->h:Ll4/d0;

    .line 41
    .line 42
    move-object v6, v5

    .line 43
    iget-object v5, v0, Lt1/p;->i:Lay0/k;

    .line 44
    .line 45
    move-object v7, v6

    .line 46
    iget-object v6, v0, Lt1/p;->j:Li1/l;

    .line 47
    .line 48
    move-object v8, v7

    .line 49
    iget-object v7, v0, Lt1/p;->k:Le3/p0;

    .line 50
    .line 51
    move-object v9, v8

    .line 52
    iget-boolean v8, v0, Lt1/p;->l:Z

    .line 53
    .line 54
    move-object v10, v9

    .line 55
    iget v9, v0, Lt1/p;->m:I

    .line 56
    .line 57
    move-object v11, v10

    .line 58
    iget v10, v0, Lt1/p;->n:I

    .line 59
    .line 60
    move-object v12, v11

    .line 61
    iget-object v11, v0, Lt1/p;->o:Ll4/j;

    .line 62
    .line 63
    move-object v13, v12

    .line 64
    iget-object v12, v0, Lt1/p;->p:Lt1/n0;

    .line 65
    .line 66
    move-object v14, v13

    .line 67
    iget-boolean v13, v0, Lt1/p;->q:Z

    .line 68
    .line 69
    move-object v15, v14

    .line 70
    iget-boolean v14, v0, Lt1/p;->r:Z

    .line 71
    .line 72
    iget-object v0, v0, Lt1/p;->s:Lt2/b;

    .line 73
    .line 74
    move-object/from16 v19, v15

    .line 75
    .line 76
    move-object v15, v0

    .line 77
    move-object/from16 v0, v19

    .line 78
    .line 79
    invoke-static/range {v0 .. v18}, Lt1/l0;->g(Ll4/v;Lay0/k;Lx2/s;Lg4/p0;Ll4/d0;Lay0/k;Li1/l;Le3/p0;ZIILl4/j;Lt1/n0;ZZLt2/b;Ll2/o;II)V

    .line 80
    .line 81
    .line 82
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object v0
.end method
