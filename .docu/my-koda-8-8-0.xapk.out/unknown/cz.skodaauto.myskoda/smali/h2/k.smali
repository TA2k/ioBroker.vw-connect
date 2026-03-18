.class public final synthetic Lh2/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/a;

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Lay0/n;

.field public final synthetic i:Le3/n0;

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:J

.field public final synthetic n:F

.field public final synthetic o:Lx4/p;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JJJJFLx4/p;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/k;->d:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/k;->e:Lt2/b;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/k;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/k;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/k;->h:Lay0/n;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/k;->i:Le3/n0;

    .line 15
    .line 16
    iput-wide p7, p0, Lh2/k;->j:J

    .line 17
    .line 18
    iput-wide p9, p0, Lh2/k;->k:J

    .line 19
    .line 20
    iput-wide p11, p0, Lh2/k;->l:J

    .line 21
    .line 22
    iput-wide p13, p0, Lh2/k;->m:J

    .line 23
    .line 24
    iput p15, p0, Lh2/k;->n:F

    .line 25
    .line 26
    move-object/from16 p1, p16

    .line 27
    .line 28
    iput-object p1, p0, Lh2/k;->o:Lx4/p;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

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
    const v1, 0x1b0031

    .line 15
    .line 16
    .line 17
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result v17

    .line 21
    iget-object v1, v0, Lh2/k;->d:Lay0/a;

    .line 22
    .line 23
    move-object v2, v1

    .line 24
    iget-object v1, v0, Lh2/k;->e:Lt2/b;

    .line 25
    .line 26
    move-object v3, v2

    .line 27
    iget-object v2, v0, Lh2/k;->f:Lx2/s;

    .line 28
    .line 29
    move-object v4, v3

    .line 30
    iget-object v3, v0, Lh2/k;->g:Lay0/n;

    .line 31
    .line 32
    move-object v5, v4

    .line 33
    iget-object v4, v0, Lh2/k;->h:Lay0/n;

    .line 34
    .line 35
    move-object v6, v5

    .line 36
    iget-object v5, v0, Lh2/k;->i:Le3/n0;

    .line 37
    .line 38
    move-object v8, v6

    .line 39
    iget-wide v6, v0, Lh2/k;->j:J

    .line 40
    .line 41
    move-object v10, v8

    .line 42
    iget-wide v8, v0, Lh2/k;->k:J

    .line 43
    .line 44
    move-object v12, v10

    .line 45
    iget-wide v10, v0, Lh2/k;->l:J

    .line 46
    .line 47
    move-object v14, v12

    .line 48
    iget-wide v12, v0, Lh2/k;->m:J

    .line 49
    .line 50
    move-object v15, v14

    .line 51
    iget v14, v0, Lh2/k;->n:F

    .line 52
    .line 53
    iget-object v0, v0, Lh2/k;->o:Lx4/p;

    .line 54
    .line 55
    move-object/from16 v18, v15

    .line 56
    .line 57
    move-object v15, v0

    .line 58
    move-object/from16 v0, v18

    .line 59
    .line 60
    invoke-static/range {v0 .. v17}, Lh2/r;->a(Lay0/a;Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JJJJFLx4/p;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object v0
.end method
