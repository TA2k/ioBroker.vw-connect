.class public final Lcm/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/f0;


# instance fields
.field public final synthetic d:I

.field public e:Z

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj01/f;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcm/e;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 5
    new-instance v0, Lu01/o;

    .line 6
    iget-object p1, p1, Lj01/f;->c:Lgw0/c;

    .line 7
    iget-object p1, p1, Lgw0/c;->g:Ljava/lang/Object;

    check-cast p1, Lu01/a0;

    .line 8
    iget-object p1, p1, Lu01/a0;->d:Lu01/f0;

    .line 9
    invoke-interface {p1}, Lu01/f0;->timeout()Lu01/j0;

    move-result-object p1

    .line 10
    invoke-direct {v0, p1}, Lu01/o;-><init>(Lu01/j0;)V

    iput-object v0, p0, Lcm/e;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lu01/f0;La2/e;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcm/e;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Lcm/e;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final F(Lu01/f;J)V
    .locals 7

    .line 1
    iget v0, p0, Lcm/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "source"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Lcm/e;->e:Z

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    iget-wide v1, p1, Lu01/f;->e:J

    .line 16
    .line 17
    const-wide/16 v3, 0x0

    .line 18
    .line 19
    move-wide v5, p2

    .line 20
    invoke-static/range {v1 .. v6}, Le01/e;->a(JJJ)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lj01/f;

    .line 26
    .line 27
    iget-object p0, p0, Lj01/f;->c:Lgw0/c;

    .line 28
    .line 29
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lu01/a0;

    .line 32
    .line 33
    invoke-virtual {p0, p1, v5, v6}, Lu01/a0;->F(Lu01/f;J)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "closed"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :pswitch_0
    move-wide v5, p2

    .line 46
    iget-boolean p2, p0, Lcm/e;->e:Z

    .line 47
    .line 48
    if-eqz p2, :cond_1

    .line 49
    .line 50
    invoke-virtual {p1, v5, v6}, Lu01/f;->skip(J)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    :try_start_0
    iget-object p2, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p2, Lu01/f0;

    .line 57
    .line 58
    invoke-interface {p2, p1, v5, v6}, Lu01/f0;->F(Lu01/f;J)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :catch_0
    move-exception v0

    .line 63
    move-object p1, v0

    .line 64
    const/4 p2, 0x1

    .line 65
    iput-boolean p2, p0, Lcm/e;->e:Z

    .line 66
    .line 67
    iget-object p0, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, La2/e;

    .line 70
    .line 71
    invoke-virtual {p0, p1}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    :goto_0
    return-void

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final close()V
    .locals 3

    .line 1
    iget v0, p0, Lcm/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lj01/f;

    .line 9
    .line 10
    iget-boolean v1, p0, Lcm/e;->e:Z

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v1, 0x1

    .line 16
    iput-boolean v1, p0, Lcm/e;->e:Z

    .line 17
    .line 18
    iget-object p0, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lu01/o;

    .line 21
    .line 22
    iget-object v1, p0, Lu01/o;->e:Lu01/j0;

    .line 23
    .line 24
    sget-object v2, Lu01/j0;->d:Lu01/i0;

    .line 25
    .line 26
    iput-object v2, p0, Lu01/o;->e:Lu01/j0;

    .line 27
    .line 28
    invoke-virtual {v1}, Lu01/j0;->a()Lu01/j0;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Lu01/j0;->b()Lu01/j0;

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x3

    .line 35
    iput p0, v0, Lj01/f;->d:I

    .line 36
    .line 37
    :goto_0
    return-void

    .line 38
    :pswitch_0
    :try_start_0
    iget-object v0, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Lu01/f0;

    .line 41
    .line 42
    invoke-interface {v0}, Lu01/f0;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :catch_0
    move-exception v0

    .line 47
    const/4 v1, 0x1

    .line 48
    iput-boolean v1, p0, Lcm/e;->e:Z

    .line 49
    .line 50
    iget-object p0, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, La2/e;

    .line 53
    .line 54
    invoke-virtual {p0, v0}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    :goto_1
    return-void

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final flush()V
    .locals 2

    .line 1
    iget v0, p0, Lcm/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lcm/e;->e:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    iget-object p0, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lj01/f;

    .line 14
    .line 15
    iget-object p0, p0, Lj01/f;->c:Lgw0/c;

    .line 16
    .line 17
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lu01/a0;

    .line 20
    .line 21
    invoke-virtual {p0}, Lu01/a0;->flush()V

    .line 22
    .line 23
    .line 24
    :goto_0
    return-void

    .line 25
    :pswitch_0
    :try_start_0
    iget-object v0, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Lu01/f0;

    .line 28
    .line 29
    invoke-interface {v0}, Lu01/f0;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    .line 32
    goto :goto_1

    .line 33
    :catch_0
    move-exception v0

    .line 34
    const/4 v1, 0x1

    .line 35
    iput-boolean v1, p0, Lcm/e;->e:Z

    .line 36
    .line 37
    iget-object p0, p0, Lcm/e;->g:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, La2/e;

    .line 40
    .line 41
    invoke-virtual {p0, v0}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    :goto_1
    return-void

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final timeout()Lu01/j0;
    .locals 1

    .line 1
    iget v0, p0, Lcm/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lu01/o;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lcm/e;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lu01/f0;

    .line 14
    .line 15
    invoke-interface {p0}, Lu01/f0;->timeout()Lu01/j0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
