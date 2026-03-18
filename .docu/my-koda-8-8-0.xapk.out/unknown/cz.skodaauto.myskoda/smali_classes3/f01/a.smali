.class public final Lf01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public d:Z

.field public final synthetic e:Lu01/h;

.field public final synthetic f:Lvv0/d;

.field public final synthetic g:Lu01/a0;


# direct methods
.method public constructor <init>(Lu01/h;Lvv0/d;Lu01/a0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf01/a;->e:Lu01/h;

    .line 5
    .line 6
    iput-object p2, p0, Lf01/a;->f:Lvv0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lf01/a;->g:Lu01/a0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 9

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    :try_start_0
    iget-object v0, p0, Lf01/a;->e:Lu01/h;

    .line 8
    .line 9
    invoke-interface {v0, p1, p2, p3}, Lu01/h0;->A(Lu01/f;J)J

    .line 10
    .line 11
    .line 12
    move-result-wide v6
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    const-wide/16 p2, -0x1

    .line 14
    .line 15
    cmp-long v0, v6, p2

    .line 16
    .line 17
    iget-object v8, p0, Lf01/a;->g:Lu01/a0;

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    iget-boolean p1, p0, Lf01/a;->d:Z

    .line 22
    .line 23
    if-nez p1, :cond_0

    .line 24
    .line 25
    iput-boolean v1, p0, Lf01/a;->d:Z

    .line 26
    .line 27
    invoke-virtual {v8}, Lu01/a0;->close()V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-wide p2

    .line 31
    :cond_1
    iget-object v3, v8, Lu01/a0;->e:Lu01/f;

    .line 32
    .line 33
    iget-wide p2, p1, Lu01/f;->e:J

    .line 34
    .line 35
    sub-long v4, p2, v6

    .line 36
    .line 37
    move-object v2, p1

    .line 38
    invoke-virtual/range {v2 .. v7}, Lu01/f;->f(Lu01/f;JJ)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v8}, Lu01/a0;->a()Lu01/g;

    .line 42
    .line 43
    .line 44
    return-wide v6

    .line 45
    :catch_0
    move-exception v0

    .line 46
    move-object p1, v0

    .line 47
    iget-boolean p2, p0, Lf01/a;->d:Z

    .line 48
    .line 49
    if-nez p2, :cond_2

    .line 50
    .line 51
    iput-boolean v1, p0, Lf01/a;->d:Z

    .line 52
    .line 53
    iget-object p0, p0, Lf01/a;->f:Lvv0/d;

    .line 54
    .line 55
    invoke-virtual {p0}, Lvv0/d;->b()V

    .line 56
    .line 57
    .line 58
    :cond_2
    throw p1
.end method

.method public final close()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lf01/a;->d:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 6
    .line 7
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 8
    .line 9
    const-string v1, "timeUnit"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const/16 v0, 0x64

    .line 15
    .line 16
    :try_start_0
    invoke-static {p0, v0}, Le01/g;->g(Lu01/h0;I)Z

    .line 17
    .line 18
    .line 19
    move-result v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    goto :goto_0

    .line 21
    :catch_0
    const/4 v0, 0x0

    .line 22
    :goto_0
    if-nez v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    iput-boolean v0, p0, Lf01/a;->d:Z

    .line 26
    .line 27
    iget-object v0, p0, Lf01/a;->f:Lvv0/d;

    .line 28
    .line 29
    invoke-virtual {v0}, Lvv0/d;->b()V

    .line 30
    .line 31
    .line 32
    :cond_0
    iget-object p0, p0, Lf01/a;->e:Lu01/h;

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lf01/a;->e:Lu01/h;

    .line 2
    .line 3
    invoke-interface {p0}, Lu01/h0;->timeout()Lu01/j0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
