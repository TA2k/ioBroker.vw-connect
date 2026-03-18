.class public final synthetic Lh2/b6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/a;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lh2/r8;

.field public final synthetic g:F

.field public final synthetic h:Z

.field public final synthetic i:Le3/n0;

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:F

.field public final synthetic m:J

.field public final synthetic n:Lay0/n;

.field public final synthetic o:Lay0/n;

.field public final synthetic p:Lh2/k6;

.field public final synthetic q:Lt2/b;

.field public final synthetic r:I

.field public final synthetic s:I

.field public final synthetic t:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;Lh2/r8;FZLe3/n0;JJFJLay0/n;Lay0/n;Lh2/k6;Lt2/b;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/b6;->d:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/b6;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/b6;->f:Lh2/r8;

    .line 9
    .line 10
    iput p4, p0, Lh2/b6;->g:F

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/b6;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Lh2/b6;->i:Le3/n0;

    .line 15
    .line 16
    iput-wide p7, p0, Lh2/b6;->j:J

    .line 17
    .line 18
    iput-wide p9, p0, Lh2/b6;->k:J

    .line 19
    .line 20
    iput p11, p0, Lh2/b6;->l:F

    .line 21
    .line 22
    iput-wide p12, p0, Lh2/b6;->m:J

    .line 23
    .line 24
    iput-object p14, p0, Lh2/b6;->n:Lay0/n;

    .line 25
    .line 26
    iput-object p15, p0, Lh2/b6;->o:Lay0/n;

    .line 27
    .line 28
    move-object/from16 p1, p16

    .line 29
    .line 30
    iput-object p1, p0, Lh2/b6;->p:Lh2/k6;

    .line 31
    .line 32
    move-object/from16 p1, p17

    .line 33
    .line 34
    iput-object p1, p0, Lh2/b6;->q:Lt2/b;

    .line 35
    .line 36
    move/from16 p1, p18

    .line 37
    .line 38
    iput p1, p0, Lh2/b6;->r:I

    .line 39
    .line 40
    move/from16 p1, p19

    .line 41
    .line 42
    iput p1, p0, Lh2/b6;->s:I

    .line 43
    .line 44
    move/from16 p1, p20

    .line 45
    .line 46
    iput p1, p0, Lh2/b6;->t:I

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v17, p1

    .line 4
    .line 5
    check-cast v17, Ll2/o;

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
    iget v1, v0, Lh2/b6;->r:I

    .line 15
    .line 16
    or-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v18

    .line 22
    iget v1, v0, Lh2/b6;->s:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v19

    .line 28
    iget-object v1, v0, Lh2/b6;->d:Lay0/a;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Lh2/b6;->e:Lx2/s;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Lh2/b6;->f:Lh2/r8;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget v3, v0, Lh2/b6;->g:F

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-boolean v4, v0, Lh2/b6;->h:Z

    .line 41
    .line 42
    move-object v6, v5

    .line 43
    iget-object v5, v0, Lh2/b6;->i:Le3/n0;

    .line 44
    .line 45
    move-object v8, v6

    .line 46
    iget-wide v6, v0, Lh2/b6;->j:J

    .line 47
    .line 48
    move-object v10, v8

    .line 49
    iget-wide v8, v0, Lh2/b6;->k:J

    .line 50
    .line 51
    move-object v11, v10

    .line 52
    iget v10, v0, Lh2/b6;->l:F

    .line 53
    .line 54
    move-object v13, v11

    .line 55
    iget-wide v11, v0, Lh2/b6;->m:J

    .line 56
    .line 57
    move-object v14, v13

    .line 58
    iget-object v13, v0, Lh2/b6;->n:Lay0/n;

    .line 59
    .line 60
    move-object v15, v14

    .line 61
    iget-object v14, v0, Lh2/b6;->o:Lay0/n;

    .line 62
    .line 63
    move-object/from16 v16, v15

    .line 64
    .line 65
    iget-object v15, v0, Lh2/b6;->p:Lh2/k6;

    .line 66
    .line 67
    move-object/from16 v20, v1

    .line 68
    .line 69
    iget-object v1, v0, Lh2/b6;->q:Lt2/b;

    .line 70
    .line 71
    iget v0, v0, Lh2/b6;->t:I

    .line 72
    .line 73
    move-object/from16 v21, v20

    .line 74
    .line 75
    move/from16 v20, v0

    .line 76
    .line 77
    move-object/from16 v0, v16

    .line 78
    .line 79
    move-object/from16 v16, v1

    .line 80
    .line 81
    move-object/from16 v1, v21

    .line 82
    .line 83
    invoke-static/range {v0 .. v20}, Lh2/j6;->a(Lay0/a;Lx2/s;Lh2/r8;FZLe3/n0;JJFJLay0/n;Lay0/n;Lh2/k6;Lt2/b;Ll2/o;III)V

    .line 84
    .line 85
    .line 86
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object v0
.end method
