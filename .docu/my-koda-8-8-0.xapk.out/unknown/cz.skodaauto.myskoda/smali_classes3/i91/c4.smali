.class public final synthetic Li91/c4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Ll4/v;

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ll4/d0;

.field public final synthetic h:Li1/l;

.field public final synthetic i:Z

.field public final synthetic j:Lay0/n;

.field public final synthetic k:Lay0/n;

.field public final synthetic l:Lh2/eb;

.field public final synthetic m:Lk1/a1;


# direct methods
.method public synthetic constructor <init>(Ll4/v;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Lh2/eb;Lk1/a1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/c4;->d:Ll4/v;

    .line 5
    .line 6
    iput-boolean p2, p0, Li91/c4;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Li91/c4;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Li91/c4;->g:Ll4/d0;

    .line 11
    .line 12
    iput-object p5, p0, Li91/c4;->h:Li1/l;

    .line 13
    .line 14
    iput-boolean p6, p0, Li91/c4;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Li91/c4;->j:Lay0/n;

    .line 17
    .line 18
    iput-object p8, p0, Li91/c4;->k:Lay0/n;

    .line 19
    .line 20
    iput-object p9, p0, Li91/c4;->l:Lh2/eb;

    .line 21
    .line 22
    iput-object p10, p0, Li91/c4;->m:Lk1/a1;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    check-cast v2, Lay0/n;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ll2/o;

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
    const-string v4, "innerTextField"

    .line 20
    .line 21
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v3, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    move-object v4, v1

    .line 29
    check-cast v4, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    if-eq v4, v5, :cond_2

    .line 46
    .line 47
    const/4 v4, 0x1

    .line 48
    goto :goto_1

    .line 49
    :cond_2
    const/4 v4, 0x0

    .line 50
    :goto_1
    and-int/lit8 v5, v3, 0x1

    .line 51
    .line 52
    move-object v14, v1

    .line 53
    check-cast v14, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v14, v5, v4}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_3

    .line 60
    .line 61
    sget-object v1, Lh2/hb;->a:Lh2/hb;

    .line 62
    .line 63
    iget-object v4, v0, Li91/c4;->d:Ll4/v;

    .line 64
    .line 65
    iget-object v4, v4, Ll4/v;->a:Lg4/g;

    .line 66
    .line 67
    iget-object v4, v4, Lg4/g;->e:Ljava/lang/String;

    .line 68
    .line 69
    shl-int/lit8 v3, v3, 0x3

    .line 70
    .line 71
    and-int/lit8 v3, v3, 0x70

    .line 72
    .line 73
    const/high16 v5, 0x30000000

    .line 74
    .line 75
    or-int v15, v3, v5

    .line 76
    .line 77
    const v16, 0x6000006

    .line 78
    .line 79
    .line 80
    const v17, 0x27800

    .line 81
    .line 82
    .line 83
    iget-boolean v3, v0, Li91/c4;->e:Z

    .line 84
    .line 85
    move-object v5, v1

    .line 86
    move-object v1, v4

    .line 87
    iget-boolean v4, v0, Li91/c4;->f:Z

    .line 88
    .line 89
    move-object v6, v5

    .line 90
    iget-object v5, v0, Li91/c4;->g:Ll4/d0;

    .line 91
    .line 92
    move-object v7, v6

    .line 93
    iget-object v6, v0, Li91/c4;->h:Li1/l;

    .line 94
    .line 95
    move-object v8, v7

    .line 96
    iget-boolean v7, v0, Li91/c4;->i:Z

    .line 97
    .line 98
    move-object v9, v8

    .line 99
    iget-object v8, v0, Li91/c4;->j:Lay0/n;

    .line 100
    .line 101
    move-object v10, v9

    .line 102
    iget-object v9, v0, Li91/c4;->k:Lay0/n;

    .line 103
    .line 104
    move-object v11, v10

    .line 105
    const/4 v10, 0x0

    .line 106
    move-object v12, v11

    .line 107
    iget-object v11, v0, Li91/c4;->l:Lh2/eb;

    .line 108
    .line 109
    iget-object v0, v0, Li91/c4;->m:Lk1/a1;

    .line 110
    .line 111
    const/4 v13, 0x0

    .line 112
    move-object/from16 v18, v12

    .line 113
    .line 114
    move-object v12, v0

    .line 115
    move-object/from16 v0, v18

    .line 116
    .line 117
    invoke-virtual/range {v0 .. v17}, Lh2/hb;->b(Ljava/lang/String;Lay0/n;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Le3/n0;Lh2/eb;Lk1/z0;Lay0/n;Ll2/o;III)V

    .line 118
    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 122
    .line 123
    .line 124
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    return-object v0
.end method
