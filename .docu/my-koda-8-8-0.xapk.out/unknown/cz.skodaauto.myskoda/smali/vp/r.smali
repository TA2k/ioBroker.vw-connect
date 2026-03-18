.class public final Lvp/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:J

.field public final d:J

.field public final e:J

.field public final f:J

.field public final g:J

.field public final h:Ljava/lang/Long;

.field public final i:Ljava/lang/Long;

.field public final j:Ljava/lang/Long;

.field public final k:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;JJJJJLjava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)V
    .locals 13

    .line 1
    move-wide/from16 v0, p3

    .line 2
    .line 3
    move-wide/from16 v2, p5

    .line 4
    .line 5
    move-wide/from16 v4, p7

    .line 6
    .line 7
    move-wide/from16 v6, p11

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-wide/16 v8, 0x0

    .line 19
    .line 20
    cmp-long v10, v0, v8

    .line 21
    .line 22
    const/4 v11, 0x0

    .line 23
    const/4 v12, 0x1

    .line 24
    if-ltz v10, :cond_0

    .line 25
    .line 26
    move v10, v12

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v10, v11

    .line 29
    :goto_0
    invoke-static {v10}, Lno/c0;->a(Z)V

    .line 30
    .line 31
    .line 32
    cmp-long v10, v2, v8

    .line 33
    .line 34
    if-ltz v10, :cond_1

    .line 35
    .line 36
    move v10, v12

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v10, v11

    .line 39
    :goto_1
    invoke-static {v10}, Lno/c0;->a(Z)V

    .line 40
    .line 41
    .line 42
    cmp-long v10, v4, v8

    .line 43
    .line 44
    if-ltz v10, :cond_2

    .line 45
    .line 46
    move v10, v12

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v10, v11

    .line 49
    :goto_2
    invoke-static {v10}, Lno/c0;->a(Z)V

    .line 50
    .line 51
    .line 52
    cmp-long v8, v6, v8

    .line 53
    .line 54
    if-ltz v8, :cond_3

    .line 55
    .line 56
    move v11, v12

    .line 57
    :cond_3
    invoke-static {v11}, Lno/c0;->a(Z)V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Lvp/r;->a:Ljava/lang/String;

    .line 61
    .line 62
    iput-object p2, p0, Lvp/r;->b:Ljava/lang/String;

    .line 63
    .line 64
    iput-wide v0, p0, Lvp/r;->c:J

    .line 65
    .line 66
    iput-wide v2, p0, Lvp/r;->d:J

    .line 67
    .line 68
    iput-wide v4, p0, Lvp/r;->e:J

    .line 69
    .line 70
    move-wide/from16 p1, p9

    .line 71
    .line 72
    iput-wide p1, p0, Lvp/r;->f:J

    .line 73
    .line 74
    iput-wide v6, p0, Lvp/r;->g:J

    .line 75
    .line 76
    move-object/from16 p1, p13

    .line 77
    .line 78
    iput-object p1, p0, Lvp/r;->h:Ljava/lang/Long;

    .line 79
    .line 80
    move-object/from16 p1, p14

    .line 81
    .line 82
    iput-object p1, p0, Lvp/r;->i:Ljava/lang/Long;

    .line 83
    .line 84
    move-object/from16 p1, p15

    .line 85
    .line 86
    iput-object p1, p0, Lvp/r;->j:Ljava/lang/Long;

    .line 87
    .line 88
    move-object/from16 p1, p16

    .line 89
    .line 90
    iput-object p1, p0, Lvp/r;->k:Ljava/lang/Boolean;

    .line 91
    .line 92
    return-void
.end method


# virtual methods
.method public final a(J)Lvp/r;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lvp/r;

    .line 4
    .line 5
    iget-wide v5, v0, Lvp/r;->d:J

    .line 6
    .line 7
    iget-wide v7, v0, Lvp/r;->e:J

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    iget-object v1, v0, Lvp/r;->a:Ljava/lang/String;

    .line 11
    .line 12
    move-object v3, v2

    .line 13
    iget-object v2, v0, Lvp/r;->b:Ljava/lang/String;

    .line 14
    .line 15
    move-object v9, v3

    .line 16
    iget-wide v3, v0, Lvp/r;->c:J

    .line 17
    .line 18
    iget-wide v11, v0, Lvp/r;->g:J

    .line 19
    .line 20
    iget-object v13, v0, Lvp/r;->h:Ljava/lang/Long;

    .line 21
    .line 22
    iget-object v14, v0, Lvp/r;->i:Ljava/lang/Long;

    .line 23
    .line 24
    iget-object v15, v0, Lvp/r;->j:Ljava/lang/Long;

    .line 25
    .line 26
    iget-object v0, v0, Lvp/r;->k:Ljava/lang/Boolean;

    .line 27
    .line 28
    move-object/from16 v16, v0

    .line 29
    .line 30
    move-object v0, v9

    .line 31
    move-wide/from16 v9, p1

    .line 32
    .line 33
    invoke-direct/range {v0 .. v16}, Lvp/r;-><init>(Ljava/lang/String;Ljava/lang/String;JJJJJLjava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)V

    .line 34
    .line 35
    .line 36
    return-object v0
.end method

.method public final b(Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)Lvp/r;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lvp/r;

    .line 4
    .line 5
    move-object v2, v1

    .line 6
    iget-object v1, v0, Lvp/r;->a:Ljava/lang/String;

    .line 7
    .line 8
    move-object v3, v2

    .line 9
    iget-object v2, v0, Lvp/r;->b:Ljava/lang/String;

    .line 10
    .line 11
    move-object v5, v3

    .line 12
    iget-wide v3, v0, Lvp/r;->c:J

    .line 13
    .line 14
    move-object v7, v5

    .line 15
    iget-wide v5, v0, Lvp/r;->d:J

    .line 16
    .line 17
    move-object v9, v7

    .line 18
    iget-wide v7, v0, Lvp/r;->e:J

    .line 19
    .line 20
    move-object v11, v9

    .line 21
    iget-wide v9, v0, Lvp/r;->f:J

    .line 22
    .line 23
    move-object v13, v11

    .line 24
    iget-wide v11, v0, Lvp/r;->g:J

    .line 25
    .line 26
    iget-object v0, v0, Lvp/r;->h:Ljava/lang/Long;

    .line 27
    .line 28
    move-object v14, v13

    .line 29
    move-object v13, v0

    .line 30
    move-object v0, v14

    .line 31
    move-object/from16 v14, p1

    .line 32
    .line 33
    move-object/from16 v15, p2

    .line 34
    .line 35
    move-object/from16 v16, p3

    .line 36
    .line 37
    invoke-direct/range {v0 .. v16}, Lvp/r;-><init>(Ljava/lang/String;Ljava/lang/String;JJJJJLjava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)V

    .line 38
    .line 39
    .line 40
    move-object v13, v0

    .line 41
    return-object v13
.end method
