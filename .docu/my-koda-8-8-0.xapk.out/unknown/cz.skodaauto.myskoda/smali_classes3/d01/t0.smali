.class public final Ld01/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# instance fields
.field public final d:Ld01/k0;

.field public final e:Ld01/i0;

.field public final f:Ljava/lang/String;

.field public final g:I

.field public final h:Ld01/w;

.field public final i:Ld01/y;

.field public final j:Ld01/v0;

.field public final k:Lu01/g0;

.field public final l:Ld01/t0;

.field public final m:Ld01/t0;

.field public final n:Ld01/t0;

.field public final o:J

.field public final p:J

.field public final q:Lh01/g;

.field public final r:Ld01/y0;

.field public s:Ld01/h;

.field public final t:Z


# direct methods
.method public constructor <init>(Ld01/k0;Ld01/i0;Ljava/lang/String;ILd01/w;Ld01/y;Ld01/v0;Lu01/g0;Ld01/t0;Ld01/t0;Ld01/t0;JJLh01/g;Ld01/y0;)V
    .locals 2

    .line 1
    move-object/from16 v0, p17

    .line 2
    .line 3
    const-string v1, "request"

    .line 4
    .line 5
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "protocol"

    .line 9
    .line 10
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "message"

    .line 14
    .line 15
    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v1, "body"

    .line 19
    .line 20
    invoke-static {p7, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string v1, "trailersSource"

    .line 24
    .line 25
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Ld01/t0;->d:Ld01/k0;

    .line 32
    .line 33
    iput-object p2, p0, Ld01/t0;->e:Ld01/i0;

    .line 34
    .line 35
    iput-object p3, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 36
    .line 37
    iput p4, p0, Ld01/t0;->g:I

    .line 38
    .line 39
    iput-object p5, p0, Ld01/t0;->h:Ld01/w;

    .line 40
    .line 41
    iput-object p6, p0, Ld01/t0;->i:Ld01/y;

    .line 42
    .line 43
    iput-object p7, p0, Ld01/t0;->j:Ld01/v0;

    .line 44
    .line 45
    iput-object p8, p0, Ld01/t0;->k:Lu01/g0;

    .line 46
    .line 47
    iput-object p9, p0, Ld01/t0;->l:Ld01/t0;

    .line 48
    .line 49
    iput-object p10, p0, Ld01/t0;->m:Ld01/t0;

    .line 50
    .line 51
    iput-object p11, p0, Ld01/t0;->n:Ld01/t0;

    .line 52
    .line 53
    iput-wide p12, p0, Ld01/t0;->o:J

    .line 54
    .line 55
    move-wide/from16 p1, p14

    .line 56
    .line 57
    iput-wide p1, p0, Ld01/t0;->p:J

    .line 58
    .line 59
    move-object/from16 p1, p16

    .line 60
    .line 61
    iput-object p1, p0, Ld01/t0;->q:Lh01/g;

    .line 62
    .line 63
    iput-object v0, p0, Ld01/t0;->r:Ld01/y0;

    .line 64
    .line 65
    const/16 p1, 0xc8

    .line 66
    .line 67
    const/4 p2, 0x0

    .line 68
    if-gt p1, p4, :cond_0

    .line 69
    .line 70
    const/16 p1, 0x12c

    .line 71
    .line 72
    if-ge p4, p1, :cond_0

    .line 73
    .line 74
    const/4 p2, 0x1

    .line 75
    :cond_0
    iput-boolean p2, p0, Ld01/t0;->t:Z

    .line 76
    .line 77
    return-void
.end method

.method public static b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Ld01/t0;->i:Ld01/y;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    :cond_0
    return-object p0
.end method


# virtual methods
.method public final a()Ld01/h;
    .locals 1

    .line 1
    iget-object v0, p0, Ld01/t0;->s:Ld01/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Ld01/h;->n:Ld01/h;

    .line 6
    .line 7
    iget-object v0, p0, Ld01/t0;->i:Ld01/y;

    .line 8
    .line 9
    invoke-static {v0}, Ljp/qe;->b(Ld01/y;)Ld01/h;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Ld01/t0;->s:Ld01/h;

    .line 14
    .line 15
    :cond_0
    return-object v0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/t0;->j:Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/v0;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()Ld01/s0;
    .locals 3

    .line 1
    new-instance v0, Ld01/s0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, -0x1

    .line 7
    iput v1, v0, Ld01/s0;->c:I

    .line 8
    .line 9
    sget-object v1, Ld01/v0;->d:Ld01/u0;

    .line 10
    .line 11
    iput-object v1, v0, Ld01/s0;->g:Ld01/v0;

    .line 12
    .line 13
    sget-object v1, Ld01/y0;->v0:Ld01/r;

    .line 14
    .line 15
    iput-object v1, v0, Ld01/s0;->o:Ld01/y0;

    .line 16
    .line 17
    iget-object v1, p0, Ld01/t0;->d:Ld01/k0;

    .line 18
    .line 19
    iput-object v1, v0, Ld01/s0;->a:Ld01/k0;

    .line 20
    .line 21
    iget-object v1, p0, Ld01/t0;->e:Ld01/i0;

    .line 22
    .line 23
    iput-object v1, v0, Ld01/s0;->b:Ld01/i0;

    .line 24
    .line 25
    iget v1, p0, Ld01/t0;->g:I

    .line 26
    .line 27
    iput v1, v0, Ld01/s0;->c:I

    .line 28
    .line 29
    iget-object v1, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 30
    .line 31
    iput-object v1, v0, Ld01/s0;->d:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v1, p0, Ld01/t0;->h:Ld01/w;

    .line 34
    .line 35
    iput-object v1, v0, Ld01/s0;->e:Ld01/w;

    .line 36
    .line 37
    iget-object v1, p0, Ld01/t0;->i:Ld01/y;

    .line 38
    .line 39
    invoke-virtual {v1}, Ld01/y;->g()Ld01/x;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iput-object v1, v0, Ld01/s0;->f:Ld01/x;

    .line 44
    .line 45
    iget-object v1, p0, Ld01/t0;->j:Ld01/v0;

    .line 46
    .line 47
    iput-object v1, v0, Ld01/s0;->g:Ld01/v0;

    .line 48
    .line 49
    iget-object v1, p0, Ld01/t0;->k:Lu01/g0;

    .line 50
    .line 51
    iput-object v1, v0, Ld01/s0;->h:Lu01/g0;

    .line 52
    .line 53
    iget-object v1, p0, Ld01/t0;->l:Ld01/t0;

    .line 54
    .line 55
    iput-object v1, v0, Ld01/s0;->i:Ld01/t0;

    .line 56
    .line 57
    iget-object v1, p0, Ld01/t0;->m:Ld01/t0;

    .line 58
    .line 59
    iput-object v1, v0, Ld01/s0;->j:Ld01/t0;

    .line 60
    .line 61
    iget-object v1, p0, Ld01/t0;->n:Ld01/t0;

    .line 62
    .line 63
    iput-object v1, v0, Ld01/s0;->k:Ld01/t0;

    .line 64
    .line 65
    iget-wide v1, p0, Ld01/t0;->o:J

    .line 66
    .line 67
    iput-wide v1, v0, Ld01/s0;->l:J

    .line 68
    .line 69
    iget-wide v1, p0, Ld01/t0;->p:J

    .line 70
    .line 71
    iput-wide v1, v0, Ld01/s0;->m:J

    .line 72
    .line 73
    iget-object v1, p0, Ld01/t0;->q:Lh01/g;

    .line 74
    .line 75
    iput-object v1, v0, Ld01/s0;->n:Lh01/g;

    .line 76
    .line 77
    iget-object p0, p0, Ld01/t0;->r:Ld01/y0;

    .line 78
    .line 79
    iput-object p0, v0, Ld01/s0;->o:Ld01/y0;

    .line 80
    .line 81
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Response{protocol="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ld01/t0;->e:Ld01/i0;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", code="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Ld01/t0;->g:I

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", message="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", url="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Ld01/t0;->d:Ld01/k0;

    .line 39
    .line 40
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const/16 p0, 0x7d

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method
