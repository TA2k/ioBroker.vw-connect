.class public final synthetic Lh2/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/r8;

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:Z

.field public final synthetic h:Le3/n0;

.field public final synthetic i:J

.field public final synthetic j:J

.field public final synthetic k:F

.field public final synthetic l:F

.field public final synthetic m:Lay0/n;

.field public final synthetic n:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;FFZLe3/n0;JJFFLay0/n;Lt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/y;->d:Lh2/r8;

    .line 5
    .line 6
    iput p2, p0, Lh2/y;->e:F

    .line 7
    .line 8
    iput p3, p0, Lh2/y;->f:F

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/y;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lh2/y;->h:Le3/n0;

    .line 13
    .line 14
    iput-wide p6, p0, Lh2/y;->i:J

    .line 15
    .line 16
    iput-wide p8, p0, Lh2/y;->j:J

    .line 17
    .line 18
    iput p10, p0, Lh2/y;->k:F

    .line 19
    .line 20
    iput p11, p0, Lh2/y;->l:F

    .line 21
    .line 22
    iput-object p12, p0, Lh2/y;->m:Lay0/n;

    .line 23
    .line 24
    iput-object p13, p0, Lh2/y;->n:Lt2/b;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v13, p1

    .line 4
    .line 5
    check-cast v13, Ll2/o;

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
    move-result v14

    .line 19
    iget-object v1, v0, Lh2/y;->d:Lh2/r8;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget v1, v0, Lh2/y;->e:F

    .line 23
    .line 24
    move-object v3, v2

    .line 25
    iget v2, v0, Lh2/y;->f:F

    .line 26
    .line 27
    move-object v4, v3

    .line 28
    iget-boolean v3, v0, Lh2/y;->g:Z

    .line 29
    .line 30
    move-object v5, v4

    .line 31
    iget-object v4, v0, Lh2/y;->h:Le3/n0;

    .line 32
    .line 33
    move-object v7, v5

    .line 34
    iget-wide v5, v0, Lh2/y;->i:J

    .line 35
    .line 36
    move-object v9, v7

    .line 37
    iget-wide v7, v0, Lh2/y;->j:J

    .line 38
    .line 39
    move-object v10, v9

    .line 40
    iget v9, v0, Lh2/y;->k:F

    .line 41
    .line 42
    move-object v11, v10

    .line 43
    iget v10, v0, Lh2/y;->l:F

    .line 44
    .line 45
    move-object v12, v11

    .line 46
    iget-object v11, v0, Lh2/y;->m:Lay0/n;

    .line 47
    .line 48
    iget-object v0, v0, Lh2/y;->n:Lt2/b;

    .line 49
    .line 50
    move-object v15, v12

    .line 51
    move-object v12, v0

    .line 52
    move-object v0, v15

    .line 53
    invoke-static/range {v0 .. v14}, Lh2/r;->r(Lh2/r8;FFZLe3/n0;JJFFLay0/n;Lt2/b;Ll2/o;I)V

    .line 54
    .line 55
    .line 56
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object v0
.end method
