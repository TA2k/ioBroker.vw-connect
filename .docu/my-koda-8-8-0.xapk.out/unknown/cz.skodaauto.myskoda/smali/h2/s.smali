.class public abstract Lh2/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;

.field public final d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lob/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lh2/s;->a:Ljava/lang/Object;

    .line 2
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string p2, "getApplicationContext(...)"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 3
    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 4
    new-instance p1, Ljava/util/LinkedHashSet;

    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object p1, p0, Lh2/s;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Long;Lgy0/j;Lh2/e8;Ljava/util/Locale;)V
    .locals 3

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p2, p0, Lh2/s;->a:Ljava/lang/Object;

    .line 7
    iput-object p4, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 8
    new-instance v0, Li2/b0;

    invoke-direct {v0, p4}, Li2/b0;-><init>(Ljava/util/Locale;)V

    .line 9
    iput-object v0, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 10
    invoke-static {p3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p3

    iput-object p3, p0, Lh2/s;->d:Ljava/lang/Object;

    const/4 p3, 0x1

    if-eqz p1, :cond_0

    .line 11
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Li2/b0;->b(J)Li2/c0;

    move-result-object p1

    .line 12
    iget p4, p1, Li2/c0;->a:I

    .line 13
    invoke-virtual {p2, p4}, Lgy0/j;->i(I)Z

    move-result p2

    if-nez p2, :cond_1

    .line 14
    invoke-virtual {v0}, Li2/b0;->c()Li2/y;

    move-result-object p1

    .line 15
    iget p2, p1, Li2/y;->d:I

    .line 16
    iget p1, p1, Li2/y;->e:I

    .line 17
    invoke-static {p2, p1, p3}, Ljava/time/LocalDate;->of(III)Ljava/time/LocalDate;

    move-result-object p1

    invoke-virtual {v0, p1}, Li2/b0;->e(Ljava/time/LocalDate;)Li2/c0;

    move-result-object p1

    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {v0}, Li2/b0;->c()Li2/y;

    move-result-object p1

    .line 19
    iget p2, p1, Li2/y;->d:I

    .line 20
    iget p1, p1, Li2/y;->e:I

    .line 21
    invoke-static {p2, p1, p3}, Ljava/time/LocalDate;->of(III)Ljava/time/LocalDate;

    move-result-object p1

    invoke-virtual {v0, p1}, Li2/b0;->e(Ljava/time/LocalDate;)Li2/c0;

    move-result-object p1

    .line 22
    :cond_1
    :goto_0
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p1

    iput-object p1, p0, Lh2/s;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public abstract a()Ljava/lang/Object;
.end method

.method public b(J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Li2/b0;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Li2/b0;->b(J)Li2/c0;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object p2, p0, Lh2/s;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lgy0/j;

    .line 12
    .line 13
    iget v0, p1, Li2/c0;->a:I

    .line 14
    .line 15
    invoke-virtual {p2, v0}, Lgy0/j;->i(I)Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lh2/s;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Ll2/j1;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public c(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lh2/s;->e:Ljava/lang/Object;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    monitor-exit v0

    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    :try_start_1
    iput-object p1, p0, Lh2/s;->e:Ljava/lang/Object;

    .line 19
    .line 20
    iget-object p1, p0, Lh2/s;->d:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Ljava/util/LinkedHashSet;

    .line 23
    .line 24
    invoke-static {p1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iget-object v1, p0, Lh2/s;->a:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v1, Lob/a;

    .line 31
    .line 32
    iget-object v1, v1, Lob/a;->d:Lj0/e;

    .line 33
    .line 34
    new-instance v2, Lh0/h0;

    .line 35
    .line 36
    const/16 v3, 0x11

    .line 37
    .line 38
    invoke-direct {v2, v3, p1, p0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1, v2}, Lj0/e;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    .line 43
    .line 44
    monitor-exit v0

    .line 45
    return-void

    .line 46
    :goto_0
    monitor-exit v0

    .line 47
    throw p0
.end method

.method public abstract d()V
.end method

.method public abstract e()V
.end method
