.class public final synthetic Lxf0/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lg4/p0;

.field public final synthetic e:J

.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lvv/n0;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Z


# direct methods
.method public synthetic constructor <init>(Lg4/p0;JILx2/s;Lvv/n0;Lay0/k;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/z1;->d:Lg4/p0;

    .line 5
    .line 6
    iput-wide p2, p0, Lxf0/z1;->e:J

    .line 7
    .line 8
    iput p4, p0, Lxf0/z1;->f:I

    .line 9
    .line 10
    iput-object p5, p0, Lxf0/z1;->g:Lx2/s;

    .line 11
    .line 12
    iput-object p6, p0, Lxf0/z1;->h:Lvv/n0;

    .line 13
    .line 14
    iput-object p7, p0, Lxf0/z1;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p8, p0, Lxf0/z1;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput-boolean p9, p0, Lxf0/z1;->k:Z

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x1

    .line 19
    if-eq v3, v4, :cond_0

    .line 20
    .line 21
    move v3, v5

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v3, 0x0

    .line 24
    :goto_0
    and-int/2addr v2, v5

    .line 25
    check-cast v1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    const/16 v16, 0x0

    .line 34
    .line 35
    const v17, 0xff7ffe

    .line 36
    .line 37
    .line 38
    iget-object v3, v0, Lxf0/z1;->d:Lg4/p0;

    .line 39
    .line 40
    iget-wide v4, v0, Lxf0/z1;->e:J

    .line 41
    .line 42
    const-wide/16 v6, 0x0

    .line 43
    .line 44
    const/4 v8, 0x0

    .line 45
    const/4 v9, 0x0

    .line 46
    const-wide/16 v10, 0x0

    .line 47
    .line 48
    iget v12, v0, Lxf0/z1;->f:I

    .line 49
    .line 50
    const-wide/16 v13, 0x0

    .line 51
    .line 52
    const/4 v15, 0x0

    .line 53
    invoke-static/range {v3 .. v17}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    new-instance v3, Li80/d;

    .line 58
    .line 59
    iget-object v4, v0, Lxf0/z1;->g:Lx2/s;

    .line 60
    .line 61
    iget-object v5, v0, Lxf0/z1;->h:Lvv/n0;

    .line 62
    .line 63
    iget-object v6, v0, Lxf0/z1;->i:Lay0/k;

    .line 64
    .line 65
    iget-object v7, v0, Lxf0/z1;->j:Ljava/lang/String;

    .line 66
    .line 67
    iget-boolean v8, v0, Lxf0/z1;->k:Z

    .line 68
    .line 69
    invoke-direct/range {v3 .. v8}, Li80/d;-><init>(Lx2/s;Lvv/n0;Lay0/k;Ljava/lang/String;Z)V

    .line 70
    .line 71
    .line 72
    const v0, 0x6ada1bc2

    .line 73
    .line 74
    .line 75
    invoke-static {v0, v1, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    const/16 v3, 0x30

    .line 80
    .line 81
    invoke-static {v2, v0, v1, v3}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_1
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object v0
.end method
