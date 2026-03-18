.class public final Ltz/q1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lrz/c;

.field public final i:Lqd0/c;

.field public final j:Lrz/v;

.field public final k:Lml0/e;

.field public final l:Lwj0/x;

.field public final m:Ltr0/b;

.field public final n:Lrq0/d;

.field public final o:Lko0/f;


# direct methods
.method public constructor <init>(Lrz/c;Lqd0/c;Lrz/v;Lwj0/y;Lml0/e;Lwj0/x;Ltr0/b;Lrq0/d;Lko0/f;)V
    .locals 4

    .line 1
    new-instance v0, Ltz/o1;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v3, v2}, Ltz/o1;-><init>(Ljava/lang/String;Lxj0/f;Z)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Ltz/q1;->h:Lrz/c;

    .line 14
    .line 15
    iput-object p2, p0, Ltz/q1;->i:Lqd0/c;

    .line 16
    .line 17
    iput-object p3, p0, Ltz/q1;->j:Lrz/v;

    .line 18
    .line 19
    iput-object p5, p0, Ltz/q1;->k:Lml0/e;

    .line 20
    .line 21
    iput-object p6, p0, Ltz/q1;->l:Lwj0/x;

    .line 22
    .line 23
    iput-object p7, p0, Ltz/q1;->m:Ltr0/b;

    .line 24
    .line 25
    iput-object p8, p0, Ltz/q1;->n:Lrq0/d;

    .line 26
    .line 27
    iput-object p9, p0, Ltz/q1;->o:Lko0/f;

    .line 28
    .line 29
    invoke-virtual {p4, v3}, Lwj0/y;->a(Lxj0/b;)V

    .line 30
    .line 31
    .line 32
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    new-instance p2, Ltz/p1;

    .line 37
    .line 38
    const/4 p3, 0x1

    .line 39
    invoke-direct {p2, p0, v3, p3}, Ltz/p1;-><init>(Ltz/q1;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    const/4 p3, 0x3

    .line 43
    invoke-static {p1, v3, v3, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Ltz/q1;->h()V

    .line 47
    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final h()V
    .locals 4

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ltz/p1;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, p0, v3, v2}, Ltz/p1;-><init>(Ltz/q1;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x3

    .line 13
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 14
    .line 15
    .line 16
    return-void
.end method
