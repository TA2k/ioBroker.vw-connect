.class public abstract Lj01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Ld01/a0;

.field public final e:Lu01/o;

.field public f:Z

.field public final synthetic g:Lj01/f;


# direct methods
.method public constructor <init>(Lj01/f;Ld01/a0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "url"

    .line 5
    .line 6
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lj01/a;->g:Lj01/f;

    .line 10
    .line 11
    iput-object p2, p0, Lj01/a;->d:Ld01/a0;

    .line 12
    .line 13
    new-instance p2, Lu01/o;

    .line 14
    .line 15
    iget-object p1, p1, Lj01/f;->c:Lgw0/c;

    .line 16
    .line 17
    iget-object p1, p1, Lgw0/c;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Lu01/b0;

    .line 20
    .line 21
    iget-object p1, p1, Lu01/b0;->d:Lu01/h0;

    .line 22
    .line 23
    invoke-interface {p1}, Lu01/h0;->timeout()Lu01/j0;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-direct {p2, p1}, Lu01/o;-><init>(Lu01/j0;)V

    .line 28
    .line 29
    .line 30
    iput-object p2, p0, Lj01/a;->e:Lu01/o;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public A(Lu01/f;J)J
    .locals 2

    .line 1
    iget-object v0, p0, Lj01/a;->g:Lj01/f;

    .line 2
    .line 3
    const-string v1, "sink"

    .line 4
    .line 5
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :try_start_0
    iget-object v1, v0, Lj01/f;->c:Lgw0/c;

    .line 9
    .line 10
    iget-object v1, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lu01/b0;

    .line 13
    .line 14
    invoke-virtual {v1, p1, p2, p3}, Lu01/b0;->A(Lu01/f;J)J

    .line 15
    .line 16
    .line 17
    move-result-wide p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    return-wide p0

    .line 19
    :catch_0
    move-exception p1

    .line 20
    iget-object p2, v0, Lj01/f;->b:Li01/c;

    .line 21
    .line 22
    invoke-interface {p2}, Li01/c;->c()V

    .line 23
    .line 24
    .line 25
    sget-object p2, Lj01/f;->g:Ld01/y;

    .line 26
    .line 27
    invoke-virtual {p0, p2}, Lj01/a;->a(Ld01/y;)V

    .line 28
    .line 29
    .line 30
    throw p1
.end method

.method public final a(Ld01/y;)V
    .locals 5

    .line 1
    const-string v0, "trailers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lj01/a;->g:Lj01/f;

    .line 7
    .line 8
    iget v1, v0, Lj01/f;->d:I

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v3, 0x5

    .line 15
    if-ne v1, v3, :cond_2

    .line 16
    .line 17
    iget-object v1, p0, Lj01/a;->e:Lu01/o;

    .line 18
    .line 19
    iget-object v3, v1, Lu01/o;->e:Lu01/j0;

    .line 20
    .line 21
    sget-object v4, Lu01/j0;->d:Lu01/i0;

    .line 22
    .line 23
    iput-object v4, v1, Lu01/o;->e:Lu01/j0;

    .line 24
    .line 25
    invoke-virtual {v3}, Lu01/j0;->a()Lu01/j0;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3}, Lu01/j0;->b()Lu01/j0;

    .line 29
    .line 30
    .line 31
    iput-object p1, v0, Lj01/f;->f:Ld01/y;

    .line 32
    .line 33
    iput v2, v0, Lj01/f;->d:I

    .line 34
    .line 35
    invoke-virtual {p1}, Ld01/y;->size()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-lez v1, :cond_1

    .line 40
    .line 41
    iget-object v0, v0, Lj01/f;->a:Ld01/h0;

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    iget-object v0, v0, Ld01/h0;->j:Ld01/r;

    .line 46
    .line 47
    if-eqz v0, :cond_1

    .line 48
    .line 49
    iget-object p0, p0, Lj01/a;->d:Ld01/a0;

    .line 50
    .line 51
    invoke-static {v0, p0, p1}, Li01/e;->b(Ld01/r;Ld01/a0;Ld01/y;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    :goto_0
    return-void

    .line 55
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    new-instance p1, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    const-string v1, "state: "

    .line 60
    .line 61
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget v0, v0, Lj01/f;->d:I

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/a;->e:Lu01/o;

    .line 2
    .line 3
    return-object p0
.end method
