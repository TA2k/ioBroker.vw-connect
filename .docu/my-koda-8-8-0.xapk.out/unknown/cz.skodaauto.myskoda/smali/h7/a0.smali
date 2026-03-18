.class public final Lh7/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# instance fields
.field public final synthetic d:Lvy0/b0;

.field public final e:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic f:Lf3/d;

.field public final synthetic g:Lvy0/b0;

.field public final synthetic h:Lay0/n;

.field public final synthetic i:Ljava/util/concurrent/atomic/AtomicReference;


# direct methods
.method public constructor <init>(Lvy0/b0;Lf3/d;Lvy0/b0;Lay0/n;Ljava/util/concurrent/atomic/AtomicReference;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lh7/a0;->f:Lf3/d;

    .line 5
    .line 6
    iput-object p3, p0, Lh7/a0;->g:Lvy0/b0;

    .line 7
    .line 8
    iput-object p4, p0, Lh7/a0;->h:Lay0/n;

    .line 9
    .line 10
    iput-object p5, p0, Lh7/a0;->i:Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
    iput-object p1, p0, Lh7/a0;->d:Lvy0/b0;

    .line 13
    .line 14
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lh7/a0;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 4

    .line 1
    iget-object v0, p0, Lh7/a0;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Long;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    iget-object p0, p0, Lh7/a0;->f:Lf3/d;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 21
    .line 22
    .line 23
    move-result-wide v2

    .line 24
    sub-long/2addr v0, v2

    .line 25
    sget p0, Lmy0/c;->g:I

    .line 26
    .line 27
    sget-object p0, Lmy0/e;->g:Lmy0/e;

    .line 28
    .line 29
    invoke-static {v0, v1, p0}, Lmy0/h;->t(JLmy0/e;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    return-wide v0

    .line 34
    :cond_0
    sget p0, Lmy0/c;->g:I

    .line 35
    .line 36
    sget-wide v0, Lmy0/c;->e:J

    .line 37
    .line 38
    return-wide v0
.end method

.method public final b(J)V
    .locals 7

    .line 1
    invoke-static {p1, p2}, Lmy0/c;->e(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long v0, v0, v2

    .line 8
    .line 9
    if-gtz v0, :cond_0

    .line 10
    .line 11
    new-instance p1, Lh7/w;

    .line 12
    .line 13
    iget-object p2, p0, Lh7/a0;->h:Lay0/n;

    .line 14
    .line 15
    invoke-virtual {p2}, Ljava/lang/Object;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    const-string v0, "Timed out immediately"

    .line 20
    .line 21
    invoke-direct {p1, v0, p2}, Lh7/w;-><init>(Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lh7/a0;->g:Lvy0/b0;

    .line 25
    .line 26
    invoke-static {p0, p1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    invoke-virtual {p0}, Lh7/a0;->a()J

    .line 31
    .line 32
    .line 33
    move-result-wide v0

    .line 34
    invoke-static {v0, v1, p1, p2}, Lmy0/c;->c(JJ)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-gez v0, :cond_1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    iget-object v0, p0, Lh7/a0;->f:Lf3/d;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    invoke-static {p1, p2}, Lmy0/c;->e(J)J

    .line 51
    .line 52
    .line 53
    move-result-wide p1

    .line 54
    add-long/2addr p1, v0

    .line 55
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iget-object p2, p0, Lh7/a0;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 60
    .line 61
    invoke-virtual {p2, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    new-instance v0, Lh7/z;

    .line 65
    .line 66
    const/4 v5, 0x0

    .line 67
    const/4 v6, 0x0

    .line 68
    iget-object v2, p0, Lh7/a0;->f:Lf3/d;

    .line 69
    .line 70
    iget-object v3, p0, Lh7/a0;->g:Lvy0/b0;

    .line 71
    .line 72
    iget-object v4, p0, Lh7/a0;->h:Lay0/n;

    .line 73
    .line 74
    move-object v1, p0

    .line 75
    invoke-direct/range {v0 .. v6}, Lh7/z;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    const/4 p0, 0x3

    .line 79
    const/4 p1, 0x0

    .line 80
    invoke-static {v3, p1, p1, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    iget-object p2, v1, Lh7/a0;->i:Ljava/util/concurrent/atomic/AtomicReference;

    .line 85
    .line 86
    invoke-virtual {p2, p0}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, Lvy0/i1;

    .line 91
    .line 92
    if-eqz p0, :cond_2

    .line 93
    .line 94
    invoke-interface {p0, p1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 95
    .line 96
    .line 97
    :cond_2
    :goto_0
    return-void
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lh7/a0;->d:Lvy0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
