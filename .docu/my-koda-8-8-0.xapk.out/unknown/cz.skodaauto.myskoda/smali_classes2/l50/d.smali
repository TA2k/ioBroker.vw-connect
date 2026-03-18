.class public final Ll50/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/r;

.field public final b:Lal0/w;

.field public final c:Lal0/w0;

.field public final d:Lal0/j1;

.field public final e:Lal0/u;

.field public final f:Lal0/d;

.field public final g:Lml0/e;

.field public final h:Lpp0/l0;


# direct methods
.method public constructor <init>(Lal0/r;Lal0/w;Lal0/w0;Lal0/j1;Lal0/u;Lal0/d;Lml0/e;Lpp0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/d;->a:Lal0/r;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/d;->b:Lal0/w;

    .line 7
    .line 8
    iput-object p3, p0, Ll50/d;->c:Lal0/w0;

    .line 9
    .line 10
    iput-object p4, p0, Ll50/d;->d:Lal0/j1;

    .line 11
    .line 12
    iput-object p5, p0, Ll50/d;->e:Lal0/u;

    .line 13
    .line 14
    iput-object p6, p0, Ll50/d;->f:Lal0/d;

    .line 15
    .line 16
    iput-object p7, p0, Ll50/d;->g:Lml0/e;

    .line 17
    .line 18
    iput-object p8, p0, Ll50/d;->h:Lpp0/l0;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Ll50/d;->c:Lal0/w0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lal0/w0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    iget-object v1, p0, Ll50/d;->h:Lpp0/l0;

    .line 10
    .line 11
    invoke-virtual {v1}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lyy0/i;

    .line 16
    .line 17
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Lal0/y0;

    .line 22
    .line 23
    const/4 v3, 0x3

    .line 24
    const/16 v4, 0xb

    .line 25
    .line 26
    const/4 v5, 0x0

    .line 27
    invoke-direct {v2, v3, v5, v4}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    new-instance v3, Lbn0/f;

    .line 31
    .line 32
    const/4 v4, 0x5

    .line 33
    invoke-direct {v3, v0, v1, v2, v4}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Lrz/k;

    .line 37
    .line 38
    const/16 v1, 0x15

    .line 39
    .line 40
    invoke-direct {v0, v3, v1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 41
    .line 42
    .line 43
    new-instance v1, Lgb0/z;

    .line 44
    .line 45
    const/16 v2, 0xe

    .line 46
    .line 47
    invoke-direct {v1, v5, p0, v2}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    new-instance v1, Li50/p;

    .line 55
    .line 56
    const/16 v2, 0x13

    .line 57
    .line 58
    invoke-direct {v1, p0, v5, v2}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    new-instance p0, Lne0/n;

    .line 62
    .line 63
    const/4 v2, 0x5

    .line 64
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 65
    .line 66
    .line 67
    return-object p0
.end method
