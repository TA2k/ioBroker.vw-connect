.class public final synthetic Lf2/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/a;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z

.field public final synthetic g:Le3/n0;

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:F

.field public final synthetic k:Li1/l;

.field public final synthetic l:Lt2/b;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;ZLe3/n0;JJFLi1/l;Lt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf2/o0;->d:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lf2/o0;->e:Lx2/s;

    .line 7
    .line 8
    iput-boolean p3, p0, Lf2/o0;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lf2/o0;->g:Le3/n0;

    .line 11
    .line 12
    iput-wide p5, p0, Lf2/o0;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Lf2/o0;->i:J

    .line 15
    .line 16
    iput p9, p0, Lf2/o0;->j:F

    .line 17
    .line 18
    iput-object p10, p0, Lf2/o0;->k:Li1/l;

    .line 19
    .line 20
    iput-object p11, p0, Lf2/o0;->l:Lt2/b;

    .line 21
    .line 22
    iput p12, p0, Lf2/o0;->m:I

    .line 23
    .line 24
    iput p13, p0, Lf2/o0;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v11, p1

    .line 2
    check-cast v11, Ll2/o;

    .line 3
    .line 4
    move-object/from16 v0, p2

    .line 5
    .line 6
    check-cast v0, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget v0, p0, Lf2/o0;->m:I

    .line 12
    .line 13
    or-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v12

    .line 19
    iget-object v0, p0, Lf2/o0;->d:Lay0/a;

    .line 20
    .line 21
    iget-object v1, p0, Lf2/o0;->e:Lx2/s;

    .line 22
    .line 23
    iget-boolean v2, p0, Lf2/o0;->f:Z

    .line 24
    .line 25
    iget-object v3, p0, Lf2/o0;->g:Le3/n0;

    .line 26
    .line 27
    iget-wide v4, p0, Lf2/o0;->h:J

    .line 28
    .line 29
    iget-wide v6, p0, Lf2/o0;->i:J

    .line 30
    .line 31
    iget v8, p0, Lf2/o0;->j:F

    .line 32
    .line 33
    iget-object v9, p0, Lf2/o0;->k:Li1/l;

    .line 34
    .line 35
    iget-object v10, p0, Lf2/o0;->l:Lt2/b;

    .line 36
    .line 37
    iget v13, p0, Lf2/o0;->n:I

    .line 38
    .line 39
    invoke-static/range {v0 .. v13}, Lkp/g7;->b(Lay0/a;Lx2/s;ZLe3/n0;JJFLi1/l;Lt2/b;Ll2/o;II)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0
.end method
