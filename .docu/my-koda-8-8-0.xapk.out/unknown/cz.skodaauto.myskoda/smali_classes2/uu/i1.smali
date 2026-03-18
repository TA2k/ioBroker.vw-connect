.class public final synthetic Luu/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:[Ljava/lang/Object;

.field public final synthetic e:Luu/l1;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:F

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Z

.field public final synthetic l:F

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/k;

.field public final synthetic p:Lay0/k;

.field public final synthetic q:Lt2/b;

.field public final synthetic r:I


# direct methods
.method public synthetic constructor <init>([Ljava/lang/Object;Luu/l1;Ljava/lang/String;FJJLjava/lang/Object;ZFLay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/i1;->d:[Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Luu/i1;->e:Luu/l1;

    .line 7
    .line 8
    iput-object p3, p0, Luu/i1;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput p4, p0, Luu/i1;->g:F

    .line 11
    .line 12
    iput-wide p5, p0, Luu/i1;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Luu/i1;->i:J

    .line 15
    .line 16
    iput-object p9, p0, Luu/i1;->j:Ljava/lang/Object;

    .line 17
    .line 18
    iput-boolean p10, p0, Luu/i1;->k:Z

    .line 19
    .line 20
    iput p11, p0, Luu/i1;->l:F

    .line 21
    .line 22
    iput-object p12, p0, Luu/i1;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p13, p0, Luu/i1;->n:Lay0/k;

    .line 25
    .line 26
    iput-object p14, p0, Luu/i1;->o:Lay0/k;

    .line 27
    .line 28
    iput-object p15, p0, Luu/i1;->p:Lay0/k;

    .line 29
    .line 30
    move-object/from16 p1, p16

    .line 31
    .line 32
    iput-object p1, p0, Luu/i1;->q:Lt2/b;

    .line 33
    .line 34
    move/from16 p1, p18

    .line 35
    .line 36
    iput p1, p0, Luu/i1;->r:I

    .line 37
    .line 38
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
    const/4 v1, 0x1

    .line 15
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v17

    .line 19
    iget-object v1, v0, Luu/i1;->d:[Ljava/lang/Object;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget-object v1, v0, Luu/i1;->e:Luu/l1;

    .line 23
    .line 24
    move-object v3, v2

    .line 25
    iget-object v2, v0, Luu/i1;->f:Ljava/lang/String;

    .line 26
    .line 27
    move-object v4, v3

    .line 28
    iget v3, v0, Luu/i1;->g:F

    .line 29
    .line 30
    move-object v6, v4

    .line 31
    iget-wide v4, v0, Luu/i1;->h:J

    .line 32
    .line 33
    move-object v8, v6

    .line 34
    iget-wide v6, v0, Luu/i1;->i:J

    .line 35
    .line 36
    move-object v9, v8

    .line 37
    iget-object v8, v0, Luu/i1;->j:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v10, v9

    .line 40
    iget-boolean v9, v0, Luu/i1;->k:Z

    .line 41
    .line 42
    move-object v11, v10

    .line 43
    iget v10, v0, Luu/i1;->l:F

    .line 44
    .line 45
    move-object v12, v11

    .line 46
    iget-object v11, v0, Luu/i1;->m:Lay0/k;

    .line 47
    .line 48
    move-object v13, v12

    .line 49
    iget-object v12, v0, Luu/i1;->n:Lay0/k;

    .line 50
    .line 51
    move-object v14, v13

    .line 52
    iget-object v13, v0, Luu/i1;->o:Lay0/k;

    .line 53
    .line 54
    move-object v15, v14

    .line 55
    iget-object v14, v0, Luu/i1;->p:Lay0/k;

    .line 56
    .line 57
    move-object/from16 v18, v15

    .line 58
    .line 59
    iget-object v15, v0, Luu/i1;->q:Lt2/b;

    .line 60
    .line 61
    iget v0, v0, Luu/i1;->r:I

    .line 62
    .line 63
    move-object/from16 v19, v18

    .line 64
    .line 65
    move/from16 v18, v0

    .line 66
    .line 67
    move-object/from16 v0, v19

    .line 68
    .line 69
    invoke-static/range {v0 .. v18}, Llp/ia;->b([Ljava/lang/Object;Luu/l1;Ljava/lang/String;FJJLjava/lang/Object;ZFLay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object v0
.end method
