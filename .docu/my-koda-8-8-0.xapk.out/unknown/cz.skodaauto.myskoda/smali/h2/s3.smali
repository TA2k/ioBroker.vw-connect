.class public final synthetic Lh2/s3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/v3;

.field public final synthetic e:Ljava/lang/Long;

.field public final synthetic f:Ljava/lang/Long;

.field public final synthetic g:I

.field public final synthetic h:Lh2/g2;

.field public final synthetic i:Lx2/s;

.field public final synthetic j:J

.field public final synthetic k:Ljava/lang/String;

.field public final synthetic l:Ljava/lang/String;

.field public final synthetic m:Lt2/b;

.field public final synthetic n:Lt2/b;

.field public final synthetic o:Lt2/b;

.field public final synthetic p:Ljava/util/Locale;

.field public final synthetic q:I

.field public final synthetic r:I


# direct methods
.method public synthetic constructor <init>(Lh2/v3;Ljava/lang/Long;Ljava/lang/Long;ILh2/g2;Lx2/s;JLjava/lang/String;Ljava/lang/String;Lt2/b;Lt2/b;Lt2/b;Ljava/util/Locale;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/s3;->d:Lh2/v3;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/s3;->e:Ljava/lang/Long;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/s3;->f:Ljava/lang/Long;

    .line 9
    .line 10
    iput p4, p0, Lh2/s3;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lh2/s3;->h:Lh2/g2;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/s3;->i:Lx2/s;

    .line 15
    .line 16
    iput-wide p7, p0, Lh2/s3;->j:J

    .line 17
    .line 18
    iput-object p9, p0, Lh2/s3;->k:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p10, p0, Lh2/s3;->l:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p11, p0, Lh2/s3;->m:Lt2/b;

    .line 23
    .line 24
    iput-object p12, p0, Lh2/s3;->n:Lt2/b;

    .line 25
    .line 26
    iput-object p13, p0, Lh2/s3;->o:Lt2/b;

    .line 27
    .line 28
    iput-object p14, p0, Lh2/s3;->p:Ljava/util/Locale;

    .line 29
    .line 30
    iput p15, p0, Lh2/s3;->q:I

    .line 31
    .line 32
    move/from16 p1, p16

    .line 33
    .line 34
    iput p1, p0, Lh2/s3;->r:I

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

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
    iget v1, v0, Lh2/s3;->q:I

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
    iget v1, v0, Lh2/s3;->r:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v16

    .line 28
    iget-object v1, v0, Lh2/s3;->d:Lh2/v3;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Lh2/s3;->e:Ljava/lang/Long;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Lh2/s3;->f:Ljava/lang/Long;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget v3, v0, Lh2/s3;->g:I

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-object v4, v0, Lh2/s3;->h:Lh2/g2;

    .line 41
    .line 42
    move-object v6, v5

    .line 43
    iget-object v5, v0, Lh2/s3;->i:Lx2/s;

    .line 44
    .line 45
    move-object v8, v6

    .line 46
    iget-wide v6, v0, Lh2/s3;->j:J

    .line 47
    .line 48
    move-object v9, v8

    .line 49
    iget-object v8, v0, Lh2/s3;->k:Ljava/lang/String;

    .line 50
    .line 51
    move-object v10, v9

    .line 52
    iget-object v9, v0, Lh2/s3;->l:Ljava/lang/String;

    .line 53
    .line 54
    move-object v11, v10

    .line 55
    iget-object v10, v0, Lh2/s3;->m:Lt2/b;

    .line 56
    .line 57
    move-object v12, v11

    .line 58
    iget-object v11, v0, Lh2/s3;->n:Lt2/b;

    .line 59
    .line 60
    move-object v13, v12

    .line 61
    iget-object v12, v0, Lh2/s3;->o:Lt2/b;

    .line 62
    .line 63
    iget-object v0, v0, Lh2/s3;->p:Ljava/util/Locale;

    .line 64
    .line 65
    move-object/from16 v17, v13

    .line 66
    .line 67
    move-object v13, v0

    .line 68
    move-object/from16 v0, v17

    .line 69
    .line 70
    invoke-virtual/range {v0 .. v16}, Lh2/v3;->a(Ljava/lang/Long;Ljava/lang/Long;ILh2/g2;Lx2/s;JLjava/lang/String;Ljava/lang/String;Lt2/b;Lt2/b;Lt2/b;Ljava/util/Locale;Ll2/o;II)V

    .line 71
    .line 72
    .line 73
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    return-object v0
.end method
