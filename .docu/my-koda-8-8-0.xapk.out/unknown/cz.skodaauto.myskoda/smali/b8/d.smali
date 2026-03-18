.class public final synthetic Lb8/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;
.implements Lw7/f;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lb8/a;IJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb8/d;->f:Ljava/lang/Object;

    iput p2, p0, Lb8/d;->e:I

    iput-wide p3, p0, Lb8/d;->d:J

    return-void
.end method

.method public synthetic constructor <init>(Ll9/k;JI)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb8/d;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lb8/d;->d:J

    iput p4, p0, Lb8/d;->e:I

    return-void
.end method


# virtual methods
.method public accept(Ljava/lang/Object;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lb8/d;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ll9/k;

    .line 6
    .line 7
    move-object/from16 v2, p1

    .line 8
    .line 9
    check-cast v2, Ll9/a;

    .line 10
    .line 11
    iget-object v3, v1, Ll9/k;->h:Lt7/o;

    .line 12
    .line 13
    invoke-static {v3}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object v3, v2, Ll9/a;->a:Lhr/h0;

    .line 17
    .line 18
    iget-wide v4, v2, Ll9/a;->c:J

    .line 19
    .line 20
    invoke-static {v3, v4, v5}, Lst/b;->f(Lhr/h0;J)[B

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    iget-object v4, v1, Ll9/k;->c:Lw7/p;

    .line 25
    .line 26
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    array-length v5, v3

    .line 30
    invoke-virtual {v4, v5, v3}, Lw7/p;->G(I[B)V

    .line 31
    .line 32
    .line 33
    iget-object v5, v1, Ll9/k;->a:Lo8/i0;

    .line 34
    .line 35
    array-length v6, v3

    .line 36
    const/4 v7, 0x0

    .line 37
    invoke-interface {v5, v4, v6, v7}, Lo8/i0;->a(Lw7/p;II)V

    .line 38
    .line 39
    .line 40
    iget-wide v4, v2, Ll9/a;->b:J

    .line 41
    .line 42
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    cmp-long v2, v4, v8

    .line 48
    .line 49
    iget-wide v8, v0, Lb8/d;->d:J

    .line 50
    .line 51
    const/4 v6, 0x1

    .line 52
    const-wide v10, 0x7fffffffffffffffL

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    if-nez v2, :cond_1

    .line 58
    .line 59
    iget-object v2, v1, Ll9/k;->h:Lt7/o;

    .line 60
    .line 61
    iget-wide v4, v2, Lt7/o;->s:J

    .line 62
    .line 63
    cmp-long v2, v4, v10

    .line 64
    .line 65
    if-nez v2, :cond_0

    .line 66
    .line 67
    move v7, v6

    .line 68
    :cond_0
    invoke-static {v7}, Lw7/a;->j(Z)V

    .line 69
    .line 70
    .line 71
    :goto_0
    move-wide v11, v8

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    iget-object v2, v1, Ll9/k;->h:Lt7/o;

    .line 74
    .line 75
    iget-wide v12, v2, Lt7/o;->s:J

    .line 76
    .line 77
    cmp-long v2, v12, v10

    .line 78
    .line 79
    if-nez v2, :cond_2

    .line 80
    .line 81
    add-long/2addr v8, v4

    .line 82
    goto :goto_0

    .line 83
    :cond_2
    add-long v8, v4, v12

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :goto_1
    iget-object v10, v1, Ll9/k;->a:Lo8/i0;

    .line 87
    .line 88
    iget v0, v0, Lb8/d;->e:I

    .line 89
    .line 90
    or-int/lit8 v13, v0, 0x1

    .line 91
    .line 92
    array-length v14, v3

    .line 93
    const/4 v15, 0x0

    .line 94
    const/16 v16, 0x0

    .line 95
    .line 96
    invoke-interface/range {v10 .. v16}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 97
    .line 98
    .line 99
    return-void
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lb8/d;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lb8/a;

    .line 4
    .line 5
    check-cast p1, Lb8/j;

    .line 6
    .line 7
    iget-object v1, p1, Lb8/j;->h:Ljava/util/HashMap;

    .line 8
    .line 9
    iget-object v2, p1, Lb8/j;->i:Ljava/util/HashMap;

    .line 10
    .line 11
    iget-object v3, v0, Lb8/a;->d:Lh8/b0;

    .line 12
    .line 13
    if-eqz v3, :cond_2

    .line 14
    .line 15
    iget-object p1, p1, Lb8/j;->c:Lb8/g;

    .line 16
    .line 17
    iget-object v0, v0, Lb8/a;->b:Lt7/p0;

    .line 18
    .line 19
    invoke-virtual {p1, v0, v3}, Lb8/g;->c(Lt7/p0;Lh8/b0;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {v2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Ljava/lang/Long;

    .line 28
    .line 29
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Ljava/lang/Long;

    .line 34
    .line 35
    const-wide/16 v4, 0x0

    .line 36
    .line 37
    if-nez v0, :cond_0

    .line 38
    .line 39
    move-wide v6, v4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 42
    .line 43
    .line 44
    move-result-wide v6

    .line 45
    :goto_0
    iget-wide v8, p0, Lb8/d;->d:J

    .line 46
    .line 47
    add-long/2addr v6, v8

    .line 48
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-virtual {v2, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    if-nez v3, :cond_1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 59
    .line 60
    .line 61
    move-result-wide v4

    .line 62
    :goto_1
    iget p0, p0, Lb8/d;->e:I

    .line 63
    .line 64
    int-to-long v2, p0

    .line 65
    add-long/2addr v4, v2

    .line 66
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-virtual {v1, p1, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    :cond_2
    return-void
.end method
