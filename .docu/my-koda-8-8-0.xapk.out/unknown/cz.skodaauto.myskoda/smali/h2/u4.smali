.class public final synthetic Lh2/u4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Landroidx/compose/material3/a;

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Le1/n1;

.field public final synthetic i:Z

.field public final synthetic j:Le3/n0;

.field public final synthetic k:J

.field public final synthetic l:F

.field public final synthetic m:F

.field public final synthetic n:Lt2/b;

.field public final synthetic o:I


# direct methods
.method public synthetic constructor <init>(Landroidx/compose/material3/a;ZLay0/a;Lx2/s;Le1/n1;ZLe3/n0;JFFLt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/u4;->d:Landroidx/compose/material3/a;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/u4;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh2/u4;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/u4;->g:Lx2/s;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/u4;->h:Le1/n1;

    .line 13
    .line 14
    iput-boolean p6, p0, Lh2/u4;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Lh2/u4;->j:Le3/n0;

    .line 17
    .line 18
    iput-wide p8, p0, Lh2/u4;->k:J

    .line 19
    .line 20
    iput p10, p0, Lh2/u4;->l:F

    .line 21
    .line 22
    iput p11, p0, Lh2/u4;->m:F

    .line 23
    .line 24
    iput-object p12, p0, Lh2/u4;->n:Lt2/b;

    .line 25
    .line 26
    iput p14, p0, Lh2/u4;->o:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v12, p1

    .line 4
    .line 5
    check-cast v12, Ll2/o;

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
    const/16 v1, 0x31

    .line 15
    .line 16
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 17
    .line 18
    .line 19
    move-result v13

    .line 20
    iget v1, v0, Lh2/u4;->o:I

    .line 21
    .line 22
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 23
    .line 24
    .line 25
    move-result v14

    .line 26
    iget-object v1, v0, Lh2/u4;->d:Landroidx/compose/material3/a;

    .line 27
    .line 28
    move-object v2, v1

    .line 29
    iget-boolean v1, v0, Lh2/u4;->e:Z

    .line 30
    .line 31
    move-object v3, v2

    .line 32
    iget-object v2, v0, Lh2/u4;->f:Lay0/a;

    .line 33
    .line 34
    move-object v4, v3

    .line 35
    iget-object v3, v0, Lh2/u4;->g:Lx2/s;

    .line 36
    .line 37
    move-object v5, v4

    .line 38
    iget-object v4, v0, Lh2/u4;->h:Le1/n1;

    .line 39
    .line 40
    move-object v6, v5

    .line 41
    iget-boolean v5, v0, Lh2/u4;->i:Z

    .line 42
    .line 43
    move-object v7, v6

    .line 44
    iget-object v6, v0, Lh2/u4;->j:Le3/n0;

    .line 45
    .line 46
    move-object v9, v7

    .line 47
    iget-wide v7, v0, Lh2/u4;->k:J

    .line 48
    .line 49
    move-object v10, v9

    .line 50
    iget v9, v0, Lh2/u4;->l:F

    .line 51
    .line 52
    move-object v11, v10

    .line 53
    iget v10, v0, Lh2/u4;->m:F

    .line 54
    .line 55
    iget-object v0, v0, Lh2/u4;->n:Lt2/b;

    .line 56
    .line 57
    move-object v15, v11

    .line 58
    move-object v11, v0

    .line 59
    move-object v0, v15

    .line 60
    invoke-virtual/range {v0 .. v14}, Landroidx/compose/material3/a;->a(ZLay0/a;Lx2/s;Le1/n1;ZLe3/n0;JFFLt2/b;Ll2/o;II)V

    .line 61
    .line 62
    .line 63
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object v0
.end method
