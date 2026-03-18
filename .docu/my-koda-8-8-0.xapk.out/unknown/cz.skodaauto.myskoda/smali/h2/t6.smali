.class public final synthetic Lh2/t6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/v6;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Ll4/d0;

.field public final synthetic j:Li1/l;

.field public final synthetic k:Z

.field public final synthetic l:Lay0/n;

.field public final synthetic m:Lay0/n;

.field public final synthetic n:Lay0/n;

.field public final synthetic o:Lh2/eb;

.field public final synthetic p:Lk1/z0;

.field public final synthetic q:Lt2/b;

.field public final synthetic r:I


# direct methods
.method public synthetic constructor <init>(Lh2/v6;Ljava/lang/String;Lay0/n;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Lay0/n;Lh2/eb;Lk1/z0;Lt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/t6;->d:Lh2/v6;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/t6;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/t6;->f:Lay0/n;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/t6;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/t6;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Lh2/t6;->i:Ll4/d0;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/t6;->j:Li1/l;

    .line 17
    .line 18
    iput-boolean p8, p0, Lh2/t6;->k:Z

    .line 19
    .line 20
    iput-object p9, p0, Lh2/t6;->l:Lay0/n;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/t6;->m:Lay0/n;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/t6;->n:Lay0/n;

    .line 25
    .line 26
    iput-object p12, p0, Lh2/t6;->o:Lh2/eb;

    .line 27
    .line 28
    iput-object p13, p0, Lh2/t6;->p:Lk1/z0;

    .line 29
    .line 30
    iput-object p14, p0, Lh2/t6;->q:Lt2/b;

    .line 31
    .line 32
    iput p15, p0, Lh2/t6;->r:I

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

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
    iget v1, v0, Lh2/t6;->r:I

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
    iget-object v1, v0, Lh2/t6;->d:Lh2/v6;

    .line 23
    .line 24
    move-object v2, v1

    .line 25
    iget-object v1, v0, Lh2/t6;->e:Ljava/lang/String;

    .line 26
    .line 27
    move-object v3, v2

    .line 28
    iget-object v2, v0, Lh2/t6;->f:Lay0/n;

    .line 29
    .line 30
    move-object v4, v3

    .line 31
    iget-boolean v3, v0, Lh2/t6;->g:Z

    .line 32
    .line 33
    move-object v5, v4

    .line 34
    iget-boolean v4, v0, Lh2/t6;->h:Z

    .line 35
    .line 36
    move-object v6, v5

    .line 37
    iget-object v5, v0, Lh2/t6;->i:Ll4/d0;

    .line 38
    .line 39
    move-object v7, v6

    .line 40
    iget-object v6, v0, Lh2/t6;->j:Li1/l;

    .line 41
    .line 42
    move-object v8, v7

    .line 43
    iget-boolean v7, v0, Lh2/t6;->k:Z

    .line 44
    .line 45
    move-object v9, v8

    .line 46
    iget-object v8, v0, Lh2/t6;->l:Lay0/n;

    .line 47
    .line 48
    move-object v10, v9

    .line 49
    iget-object v9, v0, Lh2/t6;->m:Lay0/n;

    .line 50
    .line 51
    move-object v11, v10

    .line 52
    iget-object v10, v0, Lh2/t6;->n:Lay0/n;

    .line 53
    .line 54
    move-object v12, v11

    .line 55
    iget-object v11, v0, Lh2/t6;->o:Lh2/eb;

    .line 56
    .line 57
    move-object v13, v12

    .line 58
    iget-object v12, v0, Lh2/t6;->p:Lk1/z0;

    .line 59
    .line 60
    iget-object v0, v0, Lh2/t6;->q:Lt2/b;

    .line 61
    .line 62
    move-object/from16 v16, v13

    .line 63
    .line 64
    move-object v13, v0

    .line 65
    move-object/from16 v0, v16

    .line 66
    .line 67
    invoke-virtual/range {v0 .. v15}, Lh2/v6;->b(Ljava/lang/String;Lay0/n;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Lay0/n;Lh2/eb;Lk1/z0;Lt2/b;Ll2/o;I)V

    .line 68
    .line 69
    .line 70
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object v0
.end method
