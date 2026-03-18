.class public final Ls31/i;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Ljava/lang/String;

.field public final h:Lay0/k;

.field public final i:Lk31/i0;

.field public j:Li31/b;


# direct methods
.method public constructor <init>(Lz9/y;Ljava/lang/String;Lay0/k;Lk31/i0;Lk31/u;Lk31/n;Lk31/f0;)V
    .locals 16

    .line 1
    move-object/from16 v4, p0

    .line 2
    .line 3
    new-instance v5, Ls31/k;

    .line 4
    .line 5
    const/4 v13, 0x0

    .line 6
    const-string v14, ""

    .line 7
    .line 8
    const/4 v6, 0x0

    .line 9
    sget-object v7, Lmx0/s;->d:Lmx0/s;

    .line 10
    .line 11
    const/4 v8, 0x0

    .line 12
    const/4 v9, 0x0

    .line 13
    const/4 v10, 0x0

    .line 14
    const/4 v11, 0x0

    .line 15
    const/4 v12, 0x0

    .line 16
    const/4 v15, 0x0

    .line 17
    invoke-direct/range {v5 .. v15}, Ls31/k;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;ZZLjava/lang/String;Ljava/lang/Integer;)V

    .line 18
    .line 19
    .line 20
    invoke-direct {v4, v5}, Lq41/b;-><init>(Lq41/a;)V

    .line 21
    .line 22
    .line 23
    move-object/from16 v0, p1

    .line 24
    .line 25
    iput-object v0, v4, Ls31/i;->f:Lz9/y;

    .line 26
    .line 27
    move-object/from16 v0, p2

    .line 28
    .line 29
    iput-object v0, v4, Ls31/i;->g:Ljava/lang/String;

    .line 30
    .line 31
    move-object/from16 v0, p3

    .line 32
    .line 33
    iput-object v0, v4, Ls31/i;->h:Lay0/k;

    .line 34
    .line 35
    move-object/from16 v0, p4

    .line 36
    .line 37
    iput-object v0, v4, Ls31/i;->i:Lk31/i0;

    .line 38
    .line 39
    invoke-static {v4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    new-instance v0, La7/w0;

    .line 44
    .line 45
    const/4 v5, 0x0

    .line 46
    move-object/from16 v2, p5

    .line 47
    .line 48
    move-object/from16 v1, p6

    .line 49
    .line 50
    move-object/from16 v3, p7

    .line 51
    .line 52
    invoke-direct/range {v0 .. v5}, La7/w0;-><init>(Lk31/n;Lk31/u;Lk31/f0;Ls31/i;Lkotlin/coroutines/Continuation;)V

    .line 53
    .line 54
    .line 55
    const/4 v1, 0x3

    .line 56
    const/4 v2, 0x0

    .line 57
    invoke-static {v6, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 58
    .line 59
    .line 60
    return-void
.end method
