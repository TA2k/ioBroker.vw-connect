.class public final Lmd/c;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lzb/s0;

.field public final e:Lyy0/c2;


# direct methods
.method public constructor <init>(Ldd/f;Lzb/s0;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-direct {v0}, Landroidx/lifecycle/b1;-><init>()V

    .line 6
    .line 7
    .line 8
    move-object/from16 v2, p2

    .line 9
    .line 10
    iput-object v2, v0, Lmd/c;->d:Lzb/s0;

    .line 11
    .line 12
    new-instance v2, Lmd/b;

    .line 13
    .line 14
    move-object v3, v2

    .line 15
    iget-object v2, v1, Ldd/f;->d:Ljava/lang/String;

    .line 16
    .line 17
    const/16 v4, 0x14

    .line 18
    .line 19
    invoke-static {v4, v2}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    const-string v5, "..."

    .line 24
    .line 25
    invoke-virtual {v4, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    move-object v5, v3

    .line 30
    move-object v3, v4

    .line 31
    iget-object v4, v1, Ldd/f;->g:Ljava/lang/String;

    .line 32
    .line 33
    move-object v6, v5

    .line 34
    iget-object v5, v1, Ldd/f;->f:Ljava/lang/String;

    .line 35
    .line 36
    move-object v7, v6

    .line 37
    iget-object v6, v1, Ldd/f;->e:Ljava/lang/String;

    .line 38
    .line 39
    move-object v8, v7

    .line 40
    iget-object v7, v1, Ldd/f;->i:Ljava/lang/String;

    .line 41
    .line 42
    move-object v9, v8

    .line 43
    iget-object v8, v1, Ldd/f;->h:Ljava/lang/String;

    .line 44
    .line 45
    move-object v10, v9

    .line 46
    iget-object v9, v1, Ldd/f;->r:Ljava/lang/String;

    .line 47
    .line 48
    move-object v11, v10

    .line 49
    iget-object v10, v1, Ldd/f;->s:Ljava/lang/String;

    .line 50
    .line 51
    move-object v12, v11

    .line 52
    iget-object v11, v1, Ldd/f;->m:Ljava/lang/String;

    .line 53
    .line 54
    move-object v13, v12

    .line 55
    iget-object v12, v1, Ldd/f;->k:Ljava/lang/String;

    .line 56
    .line 57
    move-object v14, v13

    .line 58
    iget-object v13, v1, Ldd/f;->l:Ljava/lang/String;

    .line 59
    .line 60
    move-object v15, v14

    .line 61
    iget-object v14, v1, Ldd/f;->n:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v1, v1, Ldd/f;->o:Ljava/lang/String;

    .line 64
    .line 65
    move-object/from16 v16, v15

    .line 66
    .line 67
    move-object v15, v1

    .line 68
    move-object/from16 v1, v16

    .line 69
    .line 70
    invoke-direct/range {v1 .. v15}, Lmd/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    iput-object v1, v0, Lmd/c;->e:Lyy0/c2;

    .line 78
    .line 79
    return-void
.end method
