.class public final synthetic Li91/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lk1/h1;

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lt2/b;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Z

.field public final synthetic j:Lay0/n;

.field public final synthetic k:Z

.field public final synthetic l:Li1/l;

.field public final synthetic m:J

.field public final synthetic n:J

.field public final synthetic o:F

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Lk1/h1;ZLay0/a;Lt2/b;Lx2/s;ZLay0/n;ZLi1/l;JJFI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/g;->d:Lk1/h1;

    .line 5
    .line 6
    iput-boolean p2, p0, Li91/g;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Li91/g;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Li91/g;->g:Lt2/b;

    .line 11
    .line 12
    iput-object p5, p0, Li91/g;->h:Lx2/s;

    .line 13
    .line 14
    iput-boolean p6, p0, Li91/g;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Li91/g;->j:Lay0/n;

    .line 17
    .line 18
    iput-boolean p8, p0, Li91/g;->k:Z

    .line 19
    .line 20
    iput-object p9, p0, Li91/g;->l:Li1/l;

    .line 21
    .line 22
    iput-wide p10, p0, Li91/g;->m:J

    .line 23
    .line 24
    iput-wide p12, p0, Li91/g;->n:J

    .line 25
    .line 26
    iput p14, p0, Li91/g;->o:F

    .line 27
    .line 28
    iput p15, p0, Li91/g;->p:I

    .line 29
    .line 30
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
    iget v1, v0, Li91/g;->p:I

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
    iget-object v1, v0, Li91/g;->d:Lk1/h1;

    .line 23
    .line 24
    move-object v2, v1

    .line 25
    iget-boolean v1, v0, Li91/g;->e:Z

    .line 26
    .line 27
    move-object v3, v2

    .line 28
    iget-object v2, v0, Li91/g;->f:Lay0/a;

    .line 29
    .line 30
    move-object v4, v3

    .line 31
    iget-object v3, v0, Li91/g;->g:Lt2/b;

    .line 32
    .line 33
    move-object v5, v4

    .line 34
    iget-object v4, v0, Li91/g;->h:Lx2/s;

    .line 35
    .line 36
    move-object v6, v5

    .line 37
    iget-boolean v5, v0, Li91/g;->i:Z

    .line 38
    .line 39
    move-object v7, v6

    .line 40
    iget-object v6, v0, Li91/g;->j:Lay0/n;

    .line 41
    .line 42
    move-object v8, v7

    .line 43
    iget-boolean v7, v0, Li91/g;->k:Z

    .line 44
    .line 45
    move-object v9, v8

    .line 46
    iget-object v8, v0, Li91/g;->l:Li1/l;

    .line 47
    .line 48
    move-object v11, v9

    .line 49
    iget-wide v9, v0, Li91/g;->m:J

    .line 50
    .line 51
    move-object v13, v11

    .line 52
    iget-wide v11, v0, Li91/g;->n:J

    .line 53
    .line 54
    iget v0, v0, Li91/g;->o:F

    .line 55
    .line 56
    move-object/from16 v16, v13

    .line 57
    .line 58
    move v13, v0

    .line 59
    move-object/from16 v0, v16

    .line 60
    .line 61
    invoke-static/range {v0 .. v15}, Li91/j0;->l(Lk1/h1;ZLay0/a;Lt2/b;Lx2/s;ZLay0/n;ZLi1/l;JJFLl2/o;I)V

    .line 62
    .line 63
    .line 64
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object v0
.end method
