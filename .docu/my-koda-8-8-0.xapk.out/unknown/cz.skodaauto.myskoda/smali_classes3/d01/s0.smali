.class public final Ld01/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ld01/k0;

.field public b:Ld01/i0;

.field public c:I

.field public d:Ljava/lang/String;

.field public e:Ld01/w;

.field public f:Ld01/x;

.field public g:Ld01/v0;

.field public h:Lu01/g0;

.field public i:Ld01/t0;

.field public j:Ld01/t0;

.field public k:Ld01/t0;

.field public l:J

.field public m:J

.field public n:Lh01/g;

.field public o:Ld01/y0;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Ld01/s0;->c:I

    .line 6
    .line 7
    sget-object v0, Ld01/v0;->d:Ld01/u0;

    .line 8
    .line 9
    iput-object v0, p0, Ld01/s0;->g:Ld01/v0;

    .line 10
    .line 11
    sget-object v0, Ld01/y0;->v0:Ld01/r;

    .line 12
    .line 13
    iput-object v0, p0, Ld01/s0;->o:Ld01/y0;

    .line 14
    .line 15
    new-instance v0, Ld01/x;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-direct {v0, v2, v1}, Ld01/x;-><init>(BI)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Ld01/s0;->f:Ld01/x;

    .line 23
    .line 24
    return-void
.end method

.method public static b(Ld01/t0;Ljava/lang/String;)V
    .locals 1

    .line 1
    if-eqz p0, :cond_3

    .line 2
    .line 3
    iget-object v0, p0, Ld01/t0;->l:Ld01/t0;

    .line 4
    .line 5
    if-nez v0, :cond_2

    .line 6
    .line 7
    iget-object v0, p0, Ld01/t0;->m:Ld01/t0;

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    iget-object p0, p0, Ld01/t0;->n:Ld01/t0;

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const-string p0, ".priorResponse != null"

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p1

    .line 32
    :cond_1
    const-string p0, ".cacheResponse != null"

    .line 33
    .line 34
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p1

    .line 48
    :cond_2
    const-string p0, ".networkResponse != null"

    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 55
    .line 56
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p1

    .line 64
    :cond_3
    :goto_0
    return-void
.end method


# virtual methods
.method public final a()Ld01/t0;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v4, v0, Ld01/s0;->c:I

    .line 4
    .line 5
    if-ltz v4, :cond_3

    .line 6
    .line 7
    iget-object v1, v0, Ld01/s0;->a:Ld01/k0;

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    iget-object v2, v0, Ld01/s0;->b:Ld01/i0;

    .line 12
    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    iget-object v3, v0, Ld01/s0;->d:Ljava/lang/String;

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    iget-object v5, v0, Ld01/s0;->e:Ld01/w;

    .line 20
    .line 21
    iget-object v6, v0, Ld01/s0;->f:Ld01/x;

    .line 22
    .line 23
    invoke-virtual {v6}, Ld01/x;->j()Ld01/y;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    iget-object v7, v0, Ld01/s0;->g:Ld01/v0;

    .line 28
    .line 29
    iget-object v8, v0, Ld01/s0;->h:Lu01/g0;

    .line 30
    .line 31
    iget-object v9, v0, Ld01/s0;->i:Ld01/t0;

    .line 32
    .line 33
    iget-object v10, v0, Ld01/s0;->j:Ld01/t0;

    .line 34
    .line 35
    iget-object v11, v0, Ld01/s0;->k:Ld01/t0;

    .line 36
    .line 37
    iget-wide v12, v0, Ld01/s0;->l:J

    .line 38
    .line 39
    iget-wide v14, v0, Ld01/s0;->m:J

    .line 40
    .line 41
    move-object/from16 v16, v1

    .line 42
    .line 43
    iget-object v1, v0, Ld01/s0;->n:Lh01/g;

    .line 44
    .line 45
    iget-object v0, v0, Ld01/s0;->o:Ld01/y0;

    .line 46
    .line 47
    move-object/from16 v17, v0

    .line 48
    .line 49
    new-instance v0, Ld01/t0;

    .line 50
    .line 51
    move-object/from16 v18, v16

    .line 52
    .line 53
    move-object/from16 v16, v1

    .line 54
    .line 55
    move-object/from16 v1, v18

    .line 56
    .line 57
    invoke-direct/range {v0 .. v17}, Ld01/t0;-><init>(Ld01/k0;Ld01/i0;Ljava/lang/String;ILd01/w;Ld01/y;Ld01/v0;Lu01/g0;Ld01/t0;Ld01/t0;Ld01/t0;JJLh01/g;Ld01/y0;)V

    .line 58
    .line 59
    .line 60
    return-object v0

    .line 61
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "message == null"

    .line 64
    .line 65
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v1, "protocol == null"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 78
    .line 79
    const-string v1, "request == null"

    .line 80
    .line 81
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw v0

    .line 85
    :cond_3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string v2, "code < 0: "

    .line 88
    .line 89
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    iget v0, v0, Ld01/s0;->c:I

    .line 93
    .line 94
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 102
    .line 103
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw v1
.end method

.method public final c(Ld01/y;)V
    .locals 1

    .line 1
    const-string v0, "headers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ld01/y;->g()Ld01/x;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Ld01/s0;->f:Ld01/x;

    .line 11
    .line 12
    return-void
.end method
