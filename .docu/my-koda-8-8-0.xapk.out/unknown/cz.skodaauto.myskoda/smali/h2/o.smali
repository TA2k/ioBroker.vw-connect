.class public final synthetic Lh2/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Li2/l0;

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:Lt2/b;

.field public final synthetic k:Lg4/p0;

.field public final synthetic l:Lg4/p0;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lk1/i;

.field public final synthetic o:Lt2/b;

.field public final synthetic p:Lt2/b;

.field public final synthetic q:F


# direct methods
.method public synthetic constructor <init>(Lx2/s;Li2/l0;JJJJLt2/b;Lg4/p0;Lg4/p0;Lay0/a;Lk1/i;Lt2/b;Lt2/b;FI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/o;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/o;->e:Li2/l0;

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/o;->f:J

    .line 9
    .line 10
    iput-wide p5, p0, Lh2/o;->g:J

    .line 11
    .line 12
    iput-wide p7, p0, Lh2/o;->h:J

    .line 13
    .line 14
    iput-wide p9, p0, Lh2/o;->i:J

    .line 15
    .line 16
    iput-object p11, p0, Lh2/o;->j:Lt2/b;

    .line 17
    .line 18
    iput-object p12, p0, Lh2/o;->k:Lg4/p0;

    .line 19
    .line 20
    iput-object p13, p0, Lh2/o;->l:Lg4/p0;

    .line 21
    .line 22
    iput-object p14, p0, Lh2/o;->m:Lay0/a;

    .line 23
    .line 24
    iput-object p15, p0, Lh2/o;->n:Lk1/i;

    .line 25
    .line 26
    move-object/from16 p1, p16

    .line 27
    .line 28
    iput-object p1, p0, Lh2/o;->o:Lt2/b;

    .line 29
    .line 30
    move-object/from16 p1, p17

    .line 31
    .line 32
    iput-object p1, p0, Lh2/o;->p:Lt2/b;

    .line 33
    .line 34
    move/from16 p1, p18

    .line 35
    .line 36
    iput p1, p0, Lh2/o;->q:F

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v18, p1

    .line 4
    .line 5
    check-cast v18, Ll2/o;

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
    const/4 v1, 0x1

    .line 15
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v19

    .line 19
    iget-object v1, v0, Lh2/o;->d:Lx2/s;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget-object v1, v0, Lh2/o;->e:Li2/l0;

    .line 23
    .line 24
    move-object v4, v2

    .line 25
    iget-wide v2, v0, Lh2/o;->f:J

    .line 26
    .line 27
    move-object v6, v4

    .line 28
    iget-wide v4, v0, Lh2/o;->g:J

    .line 29
    .line 30
    move-object v8, v6

    .line 31
    iget-wide v6, v0, Lh2/o;->h:J

    .line 32
    .line 33
    move-object v10, v8

    .line 34
    iget-wide v8, v0, Lh2/o;->i:J

    .line 35
    .line 36
    move-object v11, v10

    .line 37
    iget-object v10, v0, Lh2/o;->j:Lt2/b;

    .line 38
    .line 39
    move-object v12, v11

    .line 40
    iget-object v11, v0, Lh2/o;->k:Lg4/p0;

    .line 41
    .line 42
    move-object v13, v12

    .line 43
    iget-object v12, v0, Lh2/o;->l:Lg4/p0;

    .line 44
    .line 45
    move-object v14, v13

    .line 46
    iget-object v13, v0, Lh2/o;->m:Lay0/a;

    .line 47
    .line 48
    move-object v15, v14

    .line 49
    iget-object v14, v0, Lh2/o;->n:Lk1/i;

    .line 50
    .line 51
    move-object/from16 v16, v15

    .line 52
    .line 53
    iget-object v15, v0, Lh2/o;->o:Lt2/b;

    .line 54
    .line 55
    move-object/from16 v17, v1

    .line 56
    .line 57
    iget-object v1, v0, Lh2/o;->p:Lt2/b;

    .line 58
    .line 59
    iget v0, v0, Lh2/o;->q:F

    .line 60
    .line 61
    move-object/from16 v20, v17

    .line 62
    .line 63
    move/from16 v17, v0

    .line 64
    .line 65
    move-object/from16 v0, v16

    .line 66
    .line 67
    move-object/from16 v16, v1

    .line 68
    .line 69
    move-object/from16 v1, v20

    .line 70
    .line 71
    invoke-static/range {v0 .. v19}, Lh2/q;->c(Lx2/s;Li2/l0;JJJJLt2/b;Lg4/p0;Lg4/p0;Lay0/a;Lk1/i;Lt2/b;Lt2/b;FLl2/o;I)V

    .line 72
    .line 73
    .line 74
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object v0
.end method
