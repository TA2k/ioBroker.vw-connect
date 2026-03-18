.class public final synthetic Lh2/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lt2/b;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Le3/n0;

.field public final synthetic i:J

.field public final synthetic j:F

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:J

.field public final synthetic n:J


# direct methods
.method public synthetic constructor <init>(Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JFJJJJI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/d;->d:Lt2/b;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/d;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/d;->f:Lay0/n;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/d;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/d;->h:Le3/n0;

    .line 13
    .line 14
    iput-wide p6, p0, Lh2/d;->i:J

    .line 15
    .line 16
    iput p8, p0, Lh2/d;->j:F

    .line 17
    .line 18
    iput-wide p9, p0, Lh2/d;->k:J

    .line 19
    .line 20
    iput-wide p11, p0, Lh2/d;->l:J

    .line 21
    .line 22
    iput-wide p13, p0, Lh2/d;->m:J

    .line 23
    .line 24
    move-wide p1, p15

    .line 25
    iput-wide p1, p0, Lh2/d;->n:J

    .line 26
    .line 27
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
    const/4 v1, 0x7

    .line 15
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v17

    .line 19
    iget-object v1, v0, Lh2/d;->d:Lt2/b;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget-object v1, v0, Lh2/d;->e:Lx2/s;

    .line 23
    .line 24
    move-object v3, v2

    .line 25
    iget-object v2, v0, Lh2/d;->f:Lay0/n;

    .line 26
    .line 27
    move-object v4, v3

    .line 28
    iget-object v3, v0, Lh2/d;->g:Lay0/n;

    .line 29
    .line 30
    move-object v5, v4

    .line 31
    iget-object v4, v0, Lh2/d;->h:Le3/n0;

    .line 32
    .line 33
    move-object v7, v5

    .line 34
    iget-wide v5, v0, Lh2/d;->i:J

    .line 35
    .line 36
    move-object v8, v7

    .line 37
    iget v7, v0, Lh2/d;->j:F

    .line 38
    .line 39
    move-object v10, v8

    .line 40
    iget-wide v8, v0, Lh2/d;->k:J

    .line 41
    .line 42
    move-object v12, v10

    .line 43
    iget-wide v10, v0, Lh2/d;->l:J

    .line 44
    .line 45
    move-object v14, v12

    .line 46
    iget-wide v12, v0, Lh2/d;->m:J

    .line 47
    .line 48
    move-object v15, v1

    .line 49
    iget-wide v0, v0, Lh2/d;->n:J

    .line 50
    .line 51
    move-wide/from16 v18, v0

    .line 52
    .line 53
    move-object v0, v14

    .line 54
    move-object v1, v15

    .line 55
    move-wide/from16 v14, v18

    .line 56
    .line 57
    invoke-static/range {v0 .. v17}, Lh2/j;->a(Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JFJJJJLl2/o;I)V

    .line 58
    .line 59
    .line 60
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object v0
.end method
