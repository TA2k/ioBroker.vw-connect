.class public final Lq/p;
.super Lq/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/ref/WeakReference;


# direct methods
.method public constructor <init>(Lq/s;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 5
    .line 6
    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lq/p;->a:Ljava/lang/ref/WeakReference;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(ILjava/lang/CharSequence;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lq/p;->a:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lq/s;

    .line 14
    .line 15
    iget-boolean v0, v0, Lq/s;->m:Z

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lq/s;

    .line 24
    .line 25
    iget-boolean v0, v0, Lq/s;->l:Z

    .line 26
    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lq/s;

    .line 34
    .line 35
    new-instance v0, Lq/e;

    .line 36
    .line 37
    invoke-direct {v0, p1, p2}, Lq/e;-><init>(ILjava/lang/CharSequence;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, v0}, Lq/s;->a(Lq/e;)V

    .line 41
    .line 42
    .line 43
    :cond_0
    return-void
.end method

.method public final b(Lq/n;)V
    .locals 4

    .line 1
    iget-object p0, p0, Lq/p;->a:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_5

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lq/s;

    .line 14
    .line 15
    iget-boolean v0, v0, Lq/s;->l:Z

    .line 16
    .line 17
    if-eqz v0, :cond_5

    .line 18
    .line 19
    iget v0, p1, Lq/n;->b:I

    .line 20
    .line 21
    const/4 v1, -0x1

    .line 22
    if-ne v0, v1, :cond_3

    .line 23
    .line 24
    new-instance v0, Lq/n;

    .line 25
    .line 26
    iget-object p1, p1, Lq/n;->a:Lcom/google/firebase/messaging/w;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Lq/s;

    .line 33
    .line 34
    iget-object v3, v2, Lq/s;->f:Lil/g;

    .line 35
    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    iget-object v2, v2, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 39
    .line 40
    if-eqz v2, :cond_0

    .line 41
    .line 42
    const/16 v2, 0xf

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const/16 v2, 0xff

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    const/4 v2, 0x0

    .line 49
    :goto_0
    and-int/lit16 v3, v2, 0x7fff

    .line 50
    .line 51
    if-eqz v3, :cond_2

    .line 52
    .line 53
    invoke-static {v2}, Ljp/ge;->a(I)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-nez v2, :cond_2

    .line 58
    .line 59
    const/4 v1, 0x2

    .line 60
    :cond_2
    invoke-direct {v0, p1, v1}, Lq/n;-><init>(Lcom/google/firebase/messaging/w;I)V

    .line 61
    .line 62
    .line 63
    move-object p1, v0

    .line 64
    :cond_3
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    check-cast p0, Lq/s;

    .line 69
    .line 70
    iget-object v0, p0, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 71
    .line 72
    if-nez v0, :cond_4

    .line 73
    .line 74
    new-instance v0, Landroidx/lifecycle/i0;

    .line 75
    .line 76
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 77
    .line 78
    .line 79
    iput-object v0, p0, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 80
    .line 81
    :cond_4
    iget-object p0, p0, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 82
    .line 83
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_5
    return-void
.end method
