.class public final Lc80/t;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final o:J

.field public static final synthetic p:I


# instance fields
.field public final h:Lij0/a;

.field public final i:Lzd0/a;

.field public final j:Lwq0/i;

.field public final k:Lwq0/k;

.field public final l:Lwq0/q0;

.field public final m:Lwq0/v0;

.field public n:Lvy0/x1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 4
    .line 5
    invoke-static {v0, v1, v2}, Lmy0/h;->t(JLmy0/e;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sput-wide v0, Lc80/t;->o:J

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lij0/a;Lzd0/a;Lwq0/i;Lwq0/k;Lwq0/q0;Lwq0/v0;)V
    .locals 3

    .line 1
    new-instance v0, Lc80/r;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x3ff

    .line 5
    .line 6
    invoke-direct {v0, v1, v2}, Lc80/r;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lc80/t;->h:Lij0/a;

    .line 13
    .line 14
    iput-object p2, p0, Lc80/t;->i:Lzd0/a;

    .line 15
    .line 16
    iput-object p3, p0, Lc80/t;->j:Lwq0/i;

    .line 17
    .line 18
    iput-object p4, p0, Lc80/t;->k:Lwq0/k;

    .line 19
    .line 20
    iput-object p5, p0, Lc80/t;->l:Lwq0/q0;

    .line 21
    .line 22
    iput-object p6, p0, Lc80/t;->m:Lwq0/v0;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final h()V
    .locals 4

    .line 1
    new-instance v0, Lc80/r;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v1, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    iget-object v2, p0, Lc80/t;->h:Lij0/a;

    .line 7
    .line 8
    check-cast v2, Ljj0/f;

    .line 9
    .line 10
    const v3, 0x7f121242

    .line 11
    .line 12
    .line 13
    invoke-virtual {v2, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/16 v2, 0x1ff

    .line 18
    .line 19
    invoke-direct {v0, v1, v2}, Lc80/r;-><init>(Ljava/lang/String;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    new-instance v1, Lc80/l;

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    const/4 v3, 0x0

    .line 33
    invoke-direct {v1, p0, v3, v2}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    const/4 p0, 0x3

    .line 37
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final j()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lc80/r;

    .line 6
    .line 7
    iget-object v0, v0, Lc80/r;->a:Ljava/util/List;

    .line 8
    .line 9
    move-object v1, v0

    .line 10
    check-cast v1, Ljava/lang/Iterable;

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    const/16 v6, 0x3e

    .line 14
    .line 15
    const-string v2, ""

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-static/range {v1 .. v6}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "value"

    .line 24
    .line 25
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lc80/r;

    .line 33
    .line 34
    iget-boolean v1, v1, Lc80/r;->b:Z

    .line 35
    .line 36
    if-nez v1, :cond_0

    .line 37
    .line 38
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    new-instance v2, Lc80/l;

    .line 43
    .line 44
    const/4 v3, 0x2

    .line 45
    const/4 v4, 0x0

    .line 46
    invoke-direct {v2, v3, p0, v0, v4}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 47
    .line 48
    .line 49
    const/4 p0, 0x3

    .line 50
    invoke-static {v1, v4, v4, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 51
    .line 52
    .line 53
    :cond_0
    return-void
.end method
