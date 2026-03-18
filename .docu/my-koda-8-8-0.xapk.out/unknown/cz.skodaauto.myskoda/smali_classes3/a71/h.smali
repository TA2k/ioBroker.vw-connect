.class public final synthetic La71/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lt2/b;

.field public final synthetic n:Lt2/b;


# direct methods
.method public synthetic constructor <init>(ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, La71/h;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, La71/h;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, La71/h;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, La71/h;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, La71/h;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, La71/h;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, La71/h;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, La71/h;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, La71/h;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p10, p0, La71/h;->m:Lt2/b;

    .line 23
    .line 24
    iput-object p11, p0, La71/h;->n:Lt2/b;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/q;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$FuSiScaffold"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v1, v3, 0x11

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    if-eq v1, v4, :cond_0

    .line 30
    .line 31
    move v1, v5

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v1, 0x0

    .line 34
    :goto_0
    and-int/2addr v3, v5

    .line 35
    check-cast v2, Ll2/t;

    .line 36
    .line 37
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 44
    .line 45
    const/high16 v3, 0x3f800000    # 1.0f

    .line 46
    .line 47
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    const/16 v17, 0x6

    .line 52
    .line 53
    iget-boolean v5, v0, La71/h;->d:Z

    .line 54
    .line 55
    iget-boolean v6, v0, La71/h;->e:Z

    .line 56
    .line 57
    iget-boolean v7, v0, La71/h;->f:Z

    .line 58
    .line 59
    iget-boolean v8, v0, La71/h;->g:Z

    .line 60
    .line 61
    iget-object v9, v0, La71/h;->h:Lay0/a;

    .line 62
    .line 63
    iget-object v10, v0, La71/h;->i:Lay0/a;

    .line 64
    .line 65
    iget-object v11, v0, La71/h;->j:Lay0/a;

    .line 66
    .line 67
    iget-object v12, v0, La71/h;->k:Lay0/a;

    .line 68
    .line 69
    iget-object v13, v0, La71/h;->l:Lay0/a;

    .line 70
    .line 71
    iget-object v14, v0, La71/h;->m:Lt2/b;

    .line 72
    .line 73
    iget-object v15, v0, La71/h;->n:Lt2/b;

    .line 74
    .line 75
    move-object/from16 v16, v2

    .line 76
    .line 77
    invoke-static/range {v4 .. v17}, La71/b;->e(Lx2/s;ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    move-object/from16 v16, v2

    .line 82
    .line 83
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 84
    .line 85
    .line 86
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object v0
.end method
